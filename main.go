// Command marp registers a Cloudflare WARP account on first use
// and exposes the MASQUE tunnel as an authenticated HTTP and SOCKS5 proxy.
//
// The tunnel is driven by the usque core (github.com/Diniboy1123/usque);
// account registration and configuration extraction follow the wgcf flow.
// On top of the core this program adds an endpoint pool, SNI masquerading and
// automatic QUIC -> HTTP/2 fallback.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	usqueconfig "github.com/Diniboy1123/usque/config"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"marp/internal/appconfig"
	"marp/internal/httpproxy"
	"marp/internal/socks5"
	"marp/internal/tunnel"
	"marp/internal/warpapi"
)

// version 是程序版本号。CI 编译时通过
// -ldflags "-X main.version=<tag>" 注入，默认为源码内置版本。
var version = "1.0.0"

const usage = `marp %s

用法:
  marp [run] [选项]        启动 HTTP / SOCKS5 代理（默认命令）
  marp register [选项]    强制重新注册一个 WARP 账号
  marp creds [选项]       打印当前代理认证信息
  marp version            打印版本号

选项:
`

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(os.Args[1:], logger); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		logger.Printf("错误: %v", err)
		os.Exit(1)
	}
}

// printUsage renders the top level help, including every subcommand's flags.
func printUsage() {
	fmt.Printf(usage, version)

	var (
		cfgPath, endpoints, sni, mode string
		forceNew, showCreds           bool
		license, force                string
		forceBool                     bool
	)

	runFlags := flag.NewFlagSet("run", flag.ContinueOnError)
	addConfigFlag(runFlags, &cfgPath)
	addOverrideFlags(runFlags, &endpoints, &sni, &mode)
	runFlags.BoolVar(&forceNew, "register", false, "账号配置缺失时强制重新注册")
	runFlags.StringVar(&license, "license", "", "注册后绑定的 WARP+ 许可证（可选）")
	runFlags.BoolVar(&showCreds, "creds", false, "启动时打印代理凭据")
	runFlags.SetOutput(os.Stdout)
	fmt.Println("\nrun 选项:")
	runFlags.PrintDefaults()

	registerFlags := flag.NewFlagSet("register", flag.ContinueOnError)
	addConfigFlag(registerFlags, &cfgPath)
	registerFlags.BoolVar(&forceBool, "force", false, "即使账号配置已存在也重新注册")
	registerFlags.StringVar(&license, "license", "", "注册后绑定的 WARP+ 许可证（可选）")
	registerFlags.SetOutput(os.Stdout)
	fmt.Println("\nregister 选项:")
	registerFlags.PrintDefaults()

	credsFlags := flag.NewFlagSet("creds", flag.ContinueOnError)
	addConfigFlag(credsFlags, &cfgPath)
	addOverrideFlags(credsFlags, &endpoints, &sni, &mode)
	credsFlags.SetOutput(os.Stdout)
	fmt.Println("\ncreds 选项:")
	credsFlags.PrintDefaults()

	_ = force
}

func run(args []string, logger *log.Logger) error {
	if len(args) > 0 {
		switch args[0] {
		case "run", "serve", "start":
			return runProxy(args[1:], logger)
		case "register":
			return runRegister(args[1:], logger)
		case "creds", "credentials":
			return runCreds(args[1:], logger)
		case "version", "-v", "--version":
			fmt.Println("marp", version)
			return nil
		case "help", "-h", "--help":
			printUsage()
			return nil
		}
	}
	return runProxy(args, logger)
}

// addOverrideFlags registers the transport override flags shared by run and
// creds. creds accepts them too so the effective SNI/endpoint pool can be
// previewed without starting the proxy.
func addOverrideFlags(flags *flag.FlagSet, endpoints, sni, mode *string) {
	flags.StringVar(endpoints, "endpoints", "", "覆盖端点池，逗号分隔的 ip:port，例如 162.159.198.218:443,162.159.198.20:443")
	flags.StringVar(sni, "sni", "", "覆盖 TLS SNI，可伪装为其他域名，例如 recaptcha.net")
	flags.StringVar(mode, "mode", "", "传输模式: auto (默认, QUIC 优先 + HTTP/2 回退) / quic / http2")
}

// addConfigFlag registers the configuration file flag on a flag set. The
// default is $MARP_CONFIG, then ~/.marp/config.json.
func addConfigFlag(flags *flag.FlagSet, cfgPath *string) {
	def, _ := appconfig.DefaultPath()
	flags.StringVar(cfgPath, "c", def, "应用配置文件路径（默认 ~/.marp/config.json）")
	flags.StringVar(cfgPath, "config", def, "应用配置文件路径（默认 ~/.marp/config.json）")
}

// loadConfig loads the configuration, creating it with random credentials when
// it does not exist yet. ov carries command line overrides: they are written
// into a freshly created file and applied in memory to an existing one.
func loadConfig(path string, ov appconfig.Overrides, logger *log.Logger) (appconfig.Config, error) {
	// A leftover config.json in the working directory means the user is
	// coming from an older version that stored the config next to the binary.
	if def, _ := appconfig.DefaultPath(); path == def && !fileExists(path) {
		if local := "config.json"; fileExists(local) {
			logger.Printf("提示: 当前目录下发现旧版配置 %s，将改用 %s。", local, path)
			logger.Printf("如需继续使用旧配置，请加 -c ./%s", local)
		}
	}

	cfg, created, err := appconfig.Load(path, ov)
	if err != nil {
		return cfg, err
	}
	if created {
		logger.Printf("未找到配置文件，已生成 %s", path)
		if !ov.IsZero() {
			logger.Printf("已按命令行参数写入: SNI=%s", cfg.Tunnel.SNI)
		}
		if cfg.Auth.Required() {
			logger.Printf("已生成随机代理凭据: 用户名 %q 密码 %q", cfg.Auth.Username, cfg.Auth.Password)
			logger.Printf("客户端需要使用这组凭据，请妥善保存")
		}
	} else if !ov.IsZero() {
		logger.Printf("已用命令行参数覆盖配置（文件本身未被修改）: SNI=%s", cfg.Tunnel.SNI)
	}
	return cfg, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runProxy(args []string, logger *log.Logger) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		cfgPath   string
		endpoints string
		sni       string
		mode      string
		forceNew  bool
		license   string
		showCreds bool
	)
	addConfigFlag(flags, &cfgPath)
	addOverrideFlags(flags, &endpoints, &sni, &mode)
	flags.BoolVar(&forceNew, "register", false, "账号配置缺失时强制重新注册")
	flags.StringVar(&license, "license", "", "注册后绑定的 WARP+ 许可证（可选）")
	flags.BoolVar(&showCreds, "creds", false, "启动时打印代理凭据")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(cfgPath, overridesFrom(endpoints, sni, mode), logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	accountPath := cfg.AccountPath(cfgPath)
	if forceNew {
		_ = os.Remove(accountPath)
	}

	if err := ensureAccount(ctx, cfg, accountPath, license, logger); err != nil {
		return err
	}
	if err := usqueconfig.LoadConfig(accountPath); err != nil {
		return fmt.Errorf("加载 WARP 账号配置失败: %w", err)
	}

	endpointPool, err := buildEndpoints(cfg)
	if err != nil {
		return err
	}

	device, tunNet, err := buildNetstack(cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = tunDev(device) }()

	// Hostnames are resolved inside the tunnel through the configured WARP
	// DNS servers, so clients never leak DNS to the local resolver.
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		if timeout := cfg.Tunnel.ConnectTimeoutDuration(); timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return tunNet.DialContext(ctx, "tcp", address)
	}

	// Bind before touching the network so a port conflict fails fast.
	servers, err := bindProxies(cfg, dial)
	if err != nil {
		return err
	}

	go tunnel.Run(ctx, tunnel.Options{
		TLSConfig:            tlsConfigFor(cfg, logger),
		QUICConfig:           tunnel.DefaultQUICConfig(cfg.Tunnel.KeepaliveDuration(), cfg.Tunnel.InitialPacketSize),
		Endpoints:            endpointPool,
		Mode:                 tunnel.Mode(strings.ToLower(cfg.Tunnel.Mode)),
		SNI:                  cfg.Tunnel.SNI,
		Insecure:             cfg.Tunnel.Insecure,
		Device:               device,
		MTU:                  cfg.Tunnel.MTU,
		ReconnectDelay:       cfg.Tunnel.ReconnectDelayDuration(),
		ConnectTimeout:       cfg.Tunnel.ConnectTimeoutDuration(),
		QUICFailureThreshold: cfg.Tunnel.QUICFailureThreshold,
		H2RetryInterval:      cfg.Tunnel.H2RetryIntervalDuration(),
		Logger:               logger,
		OnConnect: func(ep tunnel.Endpoint, mode tunnel.Mode) {
			logger.Printf("隧道就绪: %s via %s (SNI %s)", ep, modeLabel(mode), cfg.Tunnel.SNI)
		},
	})

	if showCreds || cfg.Auth.Required() {
		printCreds(cfg, cfgPath, endpointPool, logger)
	}

	return servers.serve(ctx, logger)
}

func modeLabel(m tunnel.Mode) string {
	if m == tunnel.ModeHTTP2 {
		return "HTTP/2(TCP)"
	}
	return "QUIC(HTTP/3)"
}

// tunDev closes the userspace TUN device.
func tunDev(dev api.TunnelDevice) error {
	if closer, ok := dev.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// overridesFrom turns the command line values into appconfig.Overrides.
func overridesFrom(endpoints, sni, mode string) appconfig.Overrides {
	return appconfig.Overrides{
		Endpoints: splitList(endpoints),
		SNI:       strings.TrimSpace(sni),
		Mode:      strings.TrimSpace(mode),
	}
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func runRegister(args []string, logger *log.Logger) error {
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	var (
		cfgPath string
		force   bool
		license string
	)
	addConfigFlag(flags, &cfgPath)
	flags.BoolVar(&force, "force", false, "即使账号配置已存在也重新注册")
	flags.StringVar(&license, "license", "", "注册后绑定的 WARP+ 许可证（可选）")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(cfgPath, appconfig.Overrides{}, logger)
	if err != nil {
		return err
	}
	accountPath := cfg.AccountPath(cfgPath)

	if _, err := os.Stat(accountPath); err == nil && !force {
		logger.Printf("账号配置已存在: %s", accountPath)
		logger.Printf("如需重新注册，请加上 -force")
		return nil
	}
	_ = os.Remove(accountPath)

	logger.Printf("正在注册新的 Cloudflare WARP 账号 ...")
	if err := warpapi.RegisterAndSave(context.Background(), accountPath, registerOptions(cfg, license)); err != nil {
		return err
	}
	logger.Printf("注册成功，账号配置已保存到 %s", accountPath)
	return nil
}

func runCreds(args []string, logger *log.Logger) error {
	flags := flag.NewFlagSet("creds", flag.ContinueOnError)
	var (
		cfgPath   string
		endpoints string
		sni       string
		mode      string
	)
	addConfigFlag(flags, &cfgPath)
	addOverrideFlags(flags, &endpoints, &sni, &mode)
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(cfgPath, overridesFrom(endpoints, sni, mode), logger)
	if err != nil {
		return err
	}
	// Best effort: include the WARP address when an account is present.
	if err := usqueconfig.LoadConfig(cfg.AccountPath(cfgPath)); err != nil {
		logger.Printf("提示: 尚未注册 WARP 账号，仅显示监听信息")
	}
	pool, err := buildEndpoints(cfg)
	if err != nil {
		pool = nil
	}
	printCreds(cfg, cfgPath, pool, logger)
	return nil
}

// ensureAccount registers a WARP account when the account file is missing.
func ensureAccount(ctx context.Context, cfg appconfig.Config, accountPath, license string, logger *log.Logger) error {
	if _, err := os.Stat(accountPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("检查账号配置失败: %w", err)
	}

	if !cfg.Warp.AutoRegister {
		return fmt.Errorf("账号配置 %s 不存在，且已关闭自动注册 (warp.auto_register)", accountPath)
	}

	logger.Printf("未找到 WARP 账号配置 %s，正在自动注册 ...", accountPath)
	if err := warpapi.RegisterAndSave(ctx, accountPath, registerOptions(cfg, license)); err != nil {
		return err
	}
	logger.Printf("WARP 账号注册成功，配置已保存到 %s", accountPath)
	return nil
}

func registerOptions(cfg appconfig.Config, license string) warpapi.RegisterOptions {
	return warpapi.RegisterOptions{
		Model:      cfg.Warp.Model,
		Locale:     cfg.Warp.Locale,
		DeviceName: cfg.Warp.DeviceName,
		TeamToken:  cfg.Warp.TeamToken,
		License:    license,
	}
}

// tlsConfigFor builds the MASQUE TLS configuration, including the (possibly
// masqueraded) SNI and the endpoint public key pinning.
func tlsConfigFor(cfg appconfig.Config, logger *log.Logger) *tls.Config {
	privKey, err := usqueconfig.AppConfig.GetEcPrivateKey()
	if err != nil {
		logger.Printf("错误: 读取设备私钥失败: %v", err)
		return nil
	}
	peerPubKey, err := usqueconfig.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		logger.Printf("错误: 读取端点公钥失败: %v", err)
		return nil
	}
	cert, err := warpapi.GenerateSelfSignedCert(privKey)
	if err != nil {
		logger.Printf("错误: 生成客户端证书失败: %v", err)
		return nil
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, cfg.Tunnel.SNI, cfg.Tunnel.Insecure)
	if err != nil {
		logger.Printf("错误: 构造 TLS 配置失败: %v", err)
		return nil
	}
	if cfg.Tunnel.Insecure {
		logger.Printf("警告: 已禁用端点公钥校验 (tunnel.insecure)")
	}
	if !tunnel.IsCloudflareSNI(cfg.Tunnel.SNI) {
		logger.Printf("SNI 伪装已启用: %s", cfg.Tunnel.SNI)
	}
	return tlsConfig
}

// buildEndpoints returns the endpoint pool: the configured list when present,
// otherwise the endpoints assigned to the WARP account.
func buildEndpoints(cfg appconfig.Config) ([]tunnel.Endpoint, error) {
	if list := splitList(strings.Join(cfg.Tunnel.Endpoints, ",")); len(list) > 0 {
		eps, err := tunnel.ParseEndpoints(list, cfg.Tunnel.Port)
		if err != nil {
			return nil, fmt.Errorf("解析 tunnel.endpoints 失败: %w", err)
		}
		return eps, nil
	}

	addr := usqueconfig.AppConfig.EndpointV4
	if cfg.Tunnel.UseIPv6 {
		addr = usqueconfig.AppConfig.EndpointV6
	}
	eps, err := tunnel.ParseEndpoints([]string{addr}, cfg.Tunnel.Port)
	if err != nil {
		return nil, fmt.Errorf("账号中的 WARP 端点无效 (%q): %w", addr, err)
	}
	return eps, nil
}

// buildNetstack creates the userspace network stack that carries the tunnelled
// traffic, so no root privileges or TUN device are required.
func buildNetstack(cfg appconfig.Config, logger *log.Logger) (api.TunnelDevice, *netstack.Net, error) {
	var localAddresses []netip.Addr
	if addr, err := netip.ParseAddr(usqueconfig.AppConfig.IPv4); err == nil {
		localAddresses = append(localAddresses, addr)
	} else {
		logger.Printf("警告: 账号中的 IPv4 地址无效 (%q)", usqueconfig.AppConfig.IPv4)
	}
	if addr, err := netip.ParseAddr(usqueconfig.AppConfig.IPv6); err == nil {
		localAddresses = append(localAddresses, addr)
	} else {
		logger.Printf("警告: 账号中的 IPv6 地址无效 (%q)", usqueconfig.AppConfig.IPv6)
	}
	if len(localAddresses) == 0 {
		return nil, nil, errors.New("账号没有可用的隧道内网地址")
	}

	var dnsAddrs []netip.Addr
	for _, server := range cfg.Tunnel.DNS {
		addr, err := netip.ParseAddr(strings.TrimSpace(server))
		if err != nil {
			return nil, nil, fmt.Errorf("无效的 DNS 服务器 %q: %w", server, err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, cfg.Tunnel.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("创建用户态网络栈失败: %w", err)
	}
	return api.NewNetstackAdapter(tunDev), tunNet, nil
}

// proxyServers bundles the two bound listeners.
type proxyServers struct {
	socks *socks5.Server
	http  *httpproxy.Server
}

// bindProxies creates and binds both listeners without serving yet, so that a
// port conflict is reported immediately and before any tunnel is started.
func bindProxies(cfg appconfig.Config, dial socks5.DialFunc) (*proxyServers, error) {
	if dial == nil {
		return nil, errors.New("缺少拨号器")
	}

	socks := &socks5.Server{
		Addr:           cfg.Listen.Socks5,
		Auth:           socks5.Credentials{Username: cfg.Auth.Username, Password: cfg.Auth.Password},
		Dial:           dial,
		ConnectTimeout: cfg.Tunnel.ConnectTimeoutDuration(),
		IdleTimeout:    5 * time.Minute,
	}
	if err := socks.Listen(); err != nil {
		return nil, err
	}

	httpSrv := &httpproxy.Server{
		Addr:           cfg.Listen.HTTP,
		Auth:           httpproxy.Credentials{Username: cfg.Auth.Username, Password: cfg.Auth.Password},
		Dial:           dial,
		Relay:          api.RelayTCP,
		ConnectTimeout: cfg.Tunnel.ConnectTimeoutDuration(),
	}
	if err := httpSrv.Listen(); err != nil {
		_ = socks.Close()
		return nil, err
	}
	return &proxyServers{socks: socks, http: httpSrv}, nil
}

// serve starts both listeners and blocks until ctx is cancelled.
func (p *proxyServers) serve(ctx context.Context, logger *log.Logger) error {
	p.socks.Logger = logger
	p.http.Logger = logger

	errs := make(chan error, 2)
	go func() {
		logger.Printf("SOCKS5 代理已监听 %s", p.socks.BoundAddr())
		if err := p.socks.Serve(); err != nil {
			errs <- err
		}
	}()
	go func() {
		logger.Printf("HTTP 代理已监听 %s", p.http.BoundAddr())
		if err := p.http.Serve(); err != nil {
			errs <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Printf("收到退出信号，正在关闭 ...")
	case err := <-errs:
		logger.Printf("监听器异常退出: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.http.Close(shutdownCtx)
	_ = p.socks.Close()
	return nil
}

// serveProxies binds both listeners and serves until ctx is cancelled. dial
// opens the outbound connection for a proxied request; in production it goes
// through the userspace tunnel stack.
func serveProxies(ctx context.Context, cfg appconfig.Config, dial socks5.DialFunc, logger *log.Logger) error {
	servers, err := bindProxies(cfg, dial)
	if err != nil {
		return err
	}
	return servers.serve(ctx, logger)
}

func printCreds(cfg appconfig.Config, cfgPath string, endpoints []tunnel.Endpoint, logger *log.Logger) {
	logger.Printf("---------------- 代理信息 ----------------")
	if cfg.Auth.Required() {
		logger.Printf("用户名 : %s", cfg.Auth.Username)
		logger.Printf("密码   : %s", cfg.Auth.Password)
		logger.Printf("HTTP   : http://%s:%s@%s", cfg.Auth.Username, cfg.Auth.Password, cfg.Listen.HTTP)
		logger.Printf("SOCKS5 : socks5://%s:%s@%s", cfg.Auth.Username, cfg.Auth.Password, cfg.Listen.Socks5)
	} else {
		logger.Printf("未启用认证")
		logger.Printf("HTTP   : http://%s", cfg.Listen.HTTP)
		logger.Printf("SOCKS5 : socks5://%s", cfg.Listen.Socks5)
	}
	if usqueconfig.AppConfig.ID != "" {
		logger.Printf("WARP IP: %s / %s", usqueconfig.AppConfig.IPv4, usqueconfig.AppConfig.IPv6)
		logger.Printf("账号   : %s", usqueconfig.AppConfig.ID)
	}
	if len(endpoints) > 0 {
		logger.Printf("端点池 : %s", tunnel.JoinEndpoints(endpoints))
	}
	logger.Printf("SNI    : %s%s", cfg.Tunnel.SNI, masqueradeHint(cfg.Tunnel.SNI))
	logger.Printf("模式   : %s", cfg.Tunnel.Mode)
	logger.Printf("配置   : %s", absolute(cfg.AccountPath(cfgPath)))
	logger.Printf("----------------------------------------")
}

func masqueradeHint(sni string) string {
	if tunnel.IsCloudflareSNI(sni) {
		return ""
	}
	return " (伪装)"
}

func absolute(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
