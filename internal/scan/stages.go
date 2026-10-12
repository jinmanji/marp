package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"marp/internal/tunnel"
)

// connectURI is the RFC 9484 Connect-URI template used by WARP.
const connectURI = "https://cloudflareaccess.com"

// tunnelQUICConfig mirrors what the running tunnel uses. Connect-IP carries
// the tunnelled IP packets as QUIC datagrams, so they must stay enabled.
func tunnelQUICConfig(mode tunnel.Mode, keepalive time.Duration) *quic.Config {
	if mode == tunnel.ModeHTTP2 {
		// HTTP/2 mode tunnels over TCP; the QUIC config is ignored.
		return nil
	}
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
	if keepalive <= 0 {
		cfg.KeepAlivePeriod = 30 * time.Second
	}
	return cfg
}

// probeStage performs one real Connect-IP handshake per candidate and mode.
//
// One attempt each, serial with a gap: the Cloudflare edge throttles bursts of
// handshakes, so a fast retry storm mostly measures the throttle rather than
// the endpoint.
func (o Options) probeStage(ctx context.Context, candidates []tunnel.Endpoint, tlsCfg *tls.Config) []probeResult {
	var (
		survivors []probeResult
		total     int
	)

	for _, ep := range candidates {
		if ctx.Err() != nil {
			break
		}
		for _, mode := range o.Modes {
			total++
			probeCtx, cancel := context.WithTimeout(ctx, o.ProbeTimeout)

			start := time.Now()
			udpConn, transport, ipConn, rsp, err := api.ConnectTunnel(
				probeCtx, tlsCfg, tunnelQUICConfig(mode, 0), connectURI,
				addrFor(ep, mode), mode == tunnel.ModeHTTP2)
			elapsed := time.Since(start)
			cancel()

			if err != nil || rsp == nil || rsp.StatusCode != http.StatusOK {
				o.logf("  握手失败 %-22s %-6s %s", ep, mode, brief(err))
				closeAll(udpConn, transport, ipConn)
			} else {
				o.logf("  握手可用 %-22s %-6s 握手 %d ms", ep, mode, elapsed.Milliseconds())
				survivors = append(survivors, probeResult{Endpoint: ep, Mode: mode, Latency: elapsed})
			}

			if !sleepCtx(ctx, o.ProbeGap) {
				return survivors
			}
		}
	}

	o.logf("握手阶段完成：%d/%d 通过", len(survivors), total)
	return survivors
}

// measureStage pulls real bytes through a throwaway tunnel for each survivor.
//
// Strictly serial with SpeedGap in between: the edge rate limits consecutive
// tunnel TCP handshakes, and probing them in parallel would make every
// candidate look slow.
func (o Options) measureStage(ctx context.Context, in []probeResult, tlsCfg *tls.Config) []Result {
	target := fmt.Sprintf(o.URL, o.ProbeBytes)

	var out []Result
	for i, p := range in {
		if ctx.Err() != nil {
			break
		}
		if i > 0 && !sleepCtx(ctx, o.SpeedGap) {
			break
		}

		mbps, err := o.measureOne(ctx, p, target, tlsCfg)
		if err != nil {
			o.logf("  测速失败 %-22s %-6s %s", p.Endpoint, p.Mode, brief(err))
			continue
		}
		o.logf("  测速完成 %-22s %-6s %.2f MB/s", p.Endpoint, p.Mode, mbps)
		out = append(out, Result{Endpoint: p.Endpoint, Mode: p.Mode, Latency: p.Latency, MBps: mbps})
	}
	return out
}

// measureOne stands up a full tunnel for a single candidate and downloads the
// probe payload through it.
func (o Options) measureOne(ctx context.Context, p probeResult, target string, tlsCfg *tls.Config) (float64, error) {
	dev, tunNet, err := o.newNetstack()
	if err != nil {
		return 0, err
	}
	defer func() { _ = dev.Close() }()

	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	connected := make(chan struct{})
	var once sync.Once
	go tunnel.Run(tunnelCtx, tunnel.Options{
		TLSConfig:      tlsCfg,
		QUICConfig:     tunnelQUICConfig(p.Mode, 0),
		Endpoints:      []tunnel.Endpoint{p.Endpoint},
		Mode:           p.Mode,
		SNI:            o.SNI,
		Insecure:       o.Insecure,
		Device:         api.NewNetstackAdapter(dev),
		MTU:            o.tunnelMTU(),
		ReconnectDelay: time.Second,
		ConnectTimeout: o.ProbeTimeout,
		OnConnect: func(tunnel.Endpoint, tunnel.Mode) {
			once.Do(func() { close(connected) })
		},
	})

	select {
	case <-connected:
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(o.ProbeTimeout + 10*time.Second):
		return 0, errors.New("隧道建立超时")
	}

	// Dial by hostname so the name is resolved by the configured in-tunnel
	// DNS (9.9.9.9 etc.), not by the host.
	//
	// Do NOT pre-resolve on the host: on networks that hijack DNS (common
	// where this runs) the host resolver returns poisoned addresses and the
	// request then stalls forever. Resolving inside the tunnel goes through
	// WARP's own resolvers and is both correct and more representative.
	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
				return tunNet.DialContext(c, "tcp", addr)
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("测速站点返回 %s", resp.Status)
	}

	start := time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, o.ProbeBytes+(1<<20)))
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	if elapsed <= 0 || n == 0 {
		return 0, errors.New("未读到数据")
	}
	return float64(n) / elapsed.Seconds() / 1e6, nil
}

// newNetstack builds a throwaway userspace stack for one measurement. The DNS
// servers come from the configuration so the measurement reflects the same
// conditions the running proxy will see.
func (o Options) newNetstack() (tun.Device, *netstack.Net, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(o.Account.IPv4); err == nil {
		addrs = append(addrs, a)
	}
	if a, err := netip.ParseAddr(o.Account.IPv6); err == nil {
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, nil, errors.New("账号没有可用的隧道内网地址")
	}

	servers := o.DNS
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "1.0.0.1"}
	}
	dns := make([]netip.Addr, 0, len(servers))
	for _, s := range servers {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			dns = append(dns, a)
		}
	}
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	return netstack.CreateNetTUN(addrs, dns, o.tunnelMTU())
}

func (o Options) tunnelMTU() int {
	if o.MTU > 0 {
		return o.MTU
	}
	return 1280
}

func addrFor(ep tunnel.Endpoint, mode tunnel.Mode) net.Addr {
	if mode == tunnel.ModeHTTP2 {
		return ep.TCPAddr()
	}
	return ep.UDPAddr()
}

func closeAll(udpConn *net.UDPConn, transport *http3.Transport, ipConn *connectip.Conn) {
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

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func brief(err error) string {
	if err == nil {
		return "无响应"
	}
	return err.Error()
}
