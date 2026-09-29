// Package tunnel supervises a Cloudflare WARP MASQUE (Connect-IP) tunnel.
//
// It wraps the usque core's ConnectTunnel helper with:
//
//   - an endpoint pool ("ip:port" entries from the configuration or the WARP
//     account), rotated on every reconnect;
//   - a QUIC (HTTP/3) first strategy with an automatic HTTP/2 (TCP) fallback
//     and periodic probing back to QUIC;
//   - packet pumping between a tun.Device (a userspace netstack in this
//     program) and the Connect-IP connection, with reconnect and backoff.
//
// The packet pump logic follows usque's api/tunnel.go (MIT licensed).
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// connectURI is the RFC 9484 Connect-URI template used by WARP.
	connectURI = "https://cloudflareaccess.com"

	// datagramContextIDHeadroom reserves one byte so connect-ip-go can encode
	// the context ID in place instead of copying the whole packet.
	datagramContextIDHeadroom = 1

	// pumpShutdownGrace bounds the wait for both pumps to exit.
	pumpShutdownGrace = 2 * time.Second

	cloudflareSNISuffix = "cloudflareclient.com"
)

// Mode selects the transport strategy used to reach the MASQUE endpoint.
type Mode string

const (
	// ModeAuto prefers QUIC and falls back to HTTP/2 when QUIC keeps failing.
	ModeAuto Mode = "auto"
	// ModeQUIC forces QUIC / HTTP3.
	ModeQUIC Mode = "quic"
	// ModeHTTP2 forces TCP + TLS + HTTP/2.
	ModeHTTP2 Mode = "http2"
)

// Options configures Run.
type Options struct {
	// TLSConfig carries the device certificate, the SNI (which may be a
	// masquerade domain) and the endpoint public key pinning.
	TLSConfig *tls.Config
	// QUICConfig is used for the QUIC transport. EnableDatagrams must be true
	// because Connect-IP carries the tunnelled IP packets as QUIC datagrams.
	QUICConfig *quic.Config
	// Endpoints is the pool to rotate through.
	Endpoints []Endpoint
	// Mode selects the transport strategy.
	Mode Mode
	// SNI is only used for logging; the value itself lives in TLSConfig.
	SNI string
	// Insecure reports whether endpoint public key pinning is disabled, in
	// which case the masquerade hint is pointless.
	Insecure bool

	Device api.TunnelDevice
	MTU    int

	// ReconnectDelay is the pause between connection attempts.
	ReconnectDelay time.Duration
	// ConnectTimeout bounds a single tunnel handshake.
	ConnectTimeout time.Duration

	// QUICFailureThreshold is how many consecutive QUIC failures are tolerated
	// before switching to HTTP/2.
	QUICFailureThreshold int
	// H2RetryInterval is how long the HTTP/2 fallback is used before probing
	// QUIC again.
	H2RetryInterval time.Duration

	Logger *log.Logger
	// OnConnect / OnDisconnect report the endpoint and transport in use.
	OnConnect    func(ep Endpoint, mode Mode)
	OnDisconnect func(ep Endpoint, mode Mode)
}

func (o *Options) applyDefaults() {
	if o.Mode == "" {
		o.Mode = ModeAuto
	}
	if o.MTU <= 0 {
		o.MTU = 1280
	}
	if o.ReconnectDelay <= 0 {
		o.ReconnectDelay = time.Second
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 15 * time.Second
	}
	if o.QUICFailureThreshold <= 0 {
		o.QUICFailureThreshold = 3
	}
	if o.H2RetryInterval <= 0 {
		o.H2RetryInterval = 5 * time.Minute
	}
	if o.QUICConfig == nil {
		o.QUICConfig = DefaultQUICConfig(30*time.Second, 0)
	}
}

// DefaultQUICConfig returns a MASQUE friendly QUIC configuration.
// An initialPacketSize of 0 keeps PMTU discovery enabled.
func DefaultQUICConfig(keepalive time.Duration, initialPacketSize uint16) *quic.Config {
	cfg := &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                keepalive,
		InitialConnectionReceiveWindow: 10_000_000,
		MaxConnectionReceiveWindow:     10_000_000,
		InitialStreamReceiveWindow:     1_000_000,
		MaxStreamReceiveWindow:         1_000_000,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
	}
	if initialPacketSize > 0 {
		cfg.InitialPacketSize = initialPacketSize
		cfg.DisablePathMTUDiscovery = true
	}
	return cfg
}

// Run keeps the tunnel alive until ctx is cancelled. It never returns a
// value; failures are logged and retried.
func Run(ctx context.Context, opts Options) {
	opts.applyDefaults()
	switch {
	case opts.TLSConfig == nil:
		opts.logf("错误: 缺少 TLS 配置")
		return
	case opts.Device == nil:
		opts.logf("错误: 缺少隧道设备")
		return
	case len(opts.Endpoints) == 0:
		opts.logf("错误: 端点列表为空")
		return
	}

	pool := append([]Endpoint(nil), opts.Endpoints...)
	buffers := api.NewNetBuffer(opts.MTU + datagramContextIDHeadroom)

	var (
		quicFailures  int
		nextQUICProbe time.Time
		cursor        int
		preferred     = ModeQUIC
	)
	if opts.Mode == ModeHTTP2 {
		preferred = ModeHTTP2
	}

	opts.logf("端点池: %s", JoinEndpoints(pool))
	opts.logf("传输模式: %s (SNI %s)", describeMode(opts.Mode), opts.SNI)

	for ctx.Err() == nil {
		// Give QUIC another chance once the fallback window elapsed.
		if preferred == ModeHTTP2 && opts.Mode == ModeAuto && !time.Now().Before(nextQUICProbe) {
			opts.logf("回切到 QUIC 探测 ...")
			preferred = ModeQUIC
			quicFailures = 0
		}

		useHTTP2 := preferred == ModeHTTP2
		ep := pool[cursor%len(pool)]
		cursor++

		err := session(ctx, opts, ep, preferred, useHTTP2, buffers)
		if ctx.Err() != nil {
			return
		}

		switch {
		case useHTTP2:
			// H2 failed too. Back off QUIC until the probe timer expires.
			if opts.Mode == ModeAuto && !time.Now().Before(nextQUICProbe) {
				preferred = ModeQUIC
				quicFailures = 0
				nextQUICProbe = time.Time{}
			}
		default:
			quicFailures++
			if opts.Mode == ModeAuto && quicFailures >= opts.QUICFailureThreshold {
				opts.logf("QUIC 连续失败 %d 次，回退到 HTTP/2，%.0fs 后再探测 QUIC",
					quicFailures, opts.H2RetryInterval.Seconds())
				preferred = ModeHTTP2
				nextQUICProbe = time.Now().Add(opts.H2RetryInterval)
			}
		}
		_ = err

		if !sleepCtx(ctx, opts.ReconnectDelay) {
			return
		}
	}
}

// session performs one connect + pump cycle and returns when the tunnel dies.
func session(ctx context.Context, opts Options, ep Endpoint, mode Mode, useHTTP2 bool, buffers *api.NetBuffer) error {
	opts.logf("正在建立 %s 隧道 -> %s", describeMode(mode), ep)

	var addr net.Addr
	if useHTTP2 {
		addr = ep.TCPAddr()
	} else {
		addr = ep.UDPAddr()
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	udpConn, transport, ipConn, rsp, err := api.ConnectTunnel(dialCtx, opts.TLSConfig, opts.QUICConfig, connectURI, addr, useHTTP2)
	cancel()

	if err != nil {
		cleanup(udpConn, transport, ipConn)
		logFailure(opts, ep, mode, err)
		return err
	}
	if rsp == nil || rsp.StatusCode != http.StatusOK {
		status := "无响应"
		if rsp != nil {
			status = rsp.Status
		}
		cleanup(udpConn, transport, ipConn)
		err = fmt.Errorf("隧道握手返回 %s", status)
		logFailure(opts, ep, mode, err)
		return err
	}

	opts.logf("%s 隧道已建立: %s", describeMode(mode), ep)
	if opts.OnConnect != nil {
		opts.OnConnect(ep, mode)
	}

	pumpErr := pump(ctx, opts, ipConn, buffers)
	opts.logf("隧道连接结束 (%s): %v", ep, pumpErr)

	if opts.OnDisconnect != nil {
		opts.OnDisconnect(ep, mode)
	}
	cleanup(udpConn, transport, ipConn)
	return pumpErr
}

// logFailure prints the failure plus the most likely explanation.
func logFailure(opts Options, ep Endpoint, mode Mode, err error) {
	opts.logf("%s 连接 %s 失败: %v", describeMode(mode), ep, err)
	hintFailure(opts, err)
}

// hintFailure classifies the common handshake failures. It deliberately keeps
// SNI masquerading and endpoint selection as separate hypotheses: a TLS level
// rejection means the endpoint does not speak MASQUE for this SNI, not that
// the SNI itself is unusable.
func hintFailure(opts Options, err error) {
	if err == nil {
		return
	}
	msg := err.Error()

	// The tunnel came up but the device key is not enrolled.
	if strings.Contains(msg, "login failed") {
		opts.logf("提示: 端点已握手成功，但设备密钥未通过入网认证。请重新注册账号，或该端点与账号所属区域不匹配。")
		return
	}

	// TLS was rejected by the peer: the endpoint answered, but not with a
	// certificate/SNI combination that accepts MASQUE.
	for _, needle := range []string{
		"CRYPTO_ERROR", "handshake failure", "tls: access denied",
		"no application protocol", "unknown authority", "bad certificate",
	} {
		if !strings.Contains(msg, needle) {
			continue
		}
		if !opts.Insecure && !IsCloudflareSNI(opts.SNI) {
			opts.logf("提示: TLS 被对端拒绝。当前 SNI=%s（伪装），若端点可信可设置 tunnel.insecure = true 重试。", opts.SNI)
		}
		opts.logf("提示: 若关闭伪装后仍然失败，说明该 IP 并不是可用的 MASQUE 端点，请换一个端点或改用账号下发的地址。")
		return
	}

	// The endpoint certificate did not match the pinned public key.
	if !opts.Insecure && strings.Contains(msg, "different public key") {
		opts.logf("提示: 端点公钥与账号记录不符，若端点可信可设置 tunnel.insecure = true。")
	}
}

// IsCloudflareSNI reports whether sni is one of Cloudflare's own MASQUE
// hostnames (as opposed to a masquerade domain).
func IsCloudflareSNI(sni string) bool {
	return strings.HasSuffix(sni, cloudflareSNISuffix)
}

// JoinEndpoints renders an endpoint pool for logging.
func JoinEndpoints(eps []Endpoint) string {
	parts := make([]string, 0, len(eps))
	for _, ep := range eps {
		parts = append(parts, ep.String())
	}
	return strings.Join(parts, ", ")
}

func describeMode(m Mode) string {
	switch m {
	case ModeHTTP2:
		return "HTTP/2(TCP)"
	case ModeQUIC:
		return "QUIC(HTTP/3)"
	default:
		return "自动(QUIC 优先, HTTP/2 回退)"
	}
}

func (o Options) logf(format string, args ...any) {
	if o.Logger != nil {
		o.Logger.Printf(format, args...)
	}
}

// cleanup releases the resources of a finished or failed tunnel session.
func cleanup(udpConn *net.UDPConn, transport *http3.Transport, ipConn *connectip.Conn) {
	if ipConn != nil {
		_ = ipConn.Close()
	}
	if transport != nil {
		_ = transport.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

// pump forwards packets between the tun device and the Connect-IP connection
// until either side fails or ctx is cancelled.
func pump(ctx context.Context, opts Options, ipConn *connectip.Conn, buffers *api.NetBuffer) error {
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var (
		wg     sync.WaitGroup
		readMu sync.Mutex
	)

	wg.Add(2)

	// tun -> tunnel
	go func() {
		defer wg.Done()
		for {
			if pumpCtx.Err() != nil {
				return
			}
			buf := buffers.Get()
			readMu.Lock()
			n, err := opts.Device.ReadPacket(buf[datagramContextIDHeadroom:])
			readMu.Unlock()
			if err != nil {
				buffers.Put(buf)
				errCh <- fmt.Errorf("从虚拟网卡读取失败: %w", err)
				return
			}
			if pumpCtx.Err() != nil {
				buffers.Put(buf)
				return
			}
			icmp, err := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
			if err != nil {
				buffers.Put(buf)
				if isConnectionClosed(err) {
					errCh <- fmt.Errorf("写入隧道时连接已关闭: %w", err)
					return
				}
				opts.logf("写入隧道出错（继续）: %v", err)
				continue
			}
			buffers.Put(buf)

			if len(icmp) > 0 {
				if err := opts.Device.WritePacket(icmp); err != nil && isConnectionClosed(err) {
					errCh <- fmt.Errorf("写入虚拟网卡时连接已关闭: %w", err)
					return
				}
			}
		}
	}()

	// tunnel -> tun
	go func() {
		defer wg.Done()
		for {
			packet, err := ipConn.ReadPacketZeroCopy(true)
			if err != nil {
				if isConnectionClosed(err) || pumpCtx.Err() != nil {
					errCh <- fmt.Errorf("从隧道读取时连接已关闭: %w", err)
					return
				}
				opts.logf("从隧道读取出错（继续）: %v", err)
				continue
			}
			if err := opts.Device.WritePacket(packet); err != nil {
				errCh <- fmt.Errorf("写入虚拟网卡失败: %w", err)
				return
			}
		}
	}()

	err := <-errCh
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(pumpShutdownGrace):
		opts.logf("数据泵关闭等待超时，可能仍有阻塞的读取协程")
	}
	return err
}

// isConnectionClosed reports whether err means the tunnel was closed.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	var closeErr *connectip.CloseError
	return errors.As(err, &closeErr)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
