// Package scan probes Cloudflare WARP MASQUE endpoints and picks the fastest
// working one.
//
// Two stages, mirroring what actually works on restrictive networks:
//
//  1. Probe — perform a real Connect-IP handshake against every candidate and
//     keep the ones that answer. This is the only honest definition of
//     "usable": ICMP reachability does not imply the edge will serve MASQUE.
//     QUIC is tried first because the edge throttles bursts of TCP handshakes
//     much more aggressively.
//  2. Measure — for the best few survivors, build a throwaway tunnel and pull
//     real bytes through it. Cloudflare rate limits consecutive tunnel TCP
//     handshakes per channel, so this stage is strictly serial with a gap.
//
// A candidate that works over QUIC but not HTTP/2 (or vice versa) is kept for
// each mode independently, because the edge throttles per channel: losing
// QUIC does not mean HTTP/2 is dead.
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/api"
	usqueconfig "github.com/Diniboy1123/usque/config"

	"marp/internal/tunnel"
	"marp/internal/warpapi"
)

// DefaultCandidates is the built-in endpoint pool. It is a deliberately short
// list rather than a /24 sweep: the edge throttles scan traffic, so probing
// hundreds of addresses mostly produces false negatives.
//
// 162.159.198.2 is what the WARP API usually hands out; .20/.218/.5 are
// measured working over HTTP/2.
var DefaultCandidates = []string{
	"162.159.198.2:443",
	"162.159.198.20:443",
	"162.159.198.218:443",
	"162.159.198.5:443",
}

// DefaultURL is the throughput probe target. Cloudflare's own speed endpoint
// keeps the measurement inside the same network as the tunnel exit.
const DefaultURL = "https://speed.cloudflare.com/__down?bytes=%d"

// Result describes one endpoint that completed both stages.
type Result struct {
	Endpoint tunnel.Endpoint
	Mode     tunnel.Mode
	Latency  time.Duration
	MBps     float64 // bytes per second / 1e6
}

// Options configures Run.
type Options struct {
	// Candidates is the explicit pool. Empty means DefaultCandidates plus the
	// endpoint stored in the account.
	Candidates []string
	// CIDR optionally widens the pool to a whole range.
	CIDR string
	// Modes to try, in order. Defaults to QUIC then HTTP/2.
	Modes []tunnel.Mode
	// SNI used for every handshake.
	SNI string
	// DNS are the resolvers the throwaway tunnel is configured with. They must
	// match the running instance: the edge silently drops some resolvers
	// inside the tunnel, so hardcoding 1.1.1.1 can make every measurement
	// fail for reasons that have nothing to do with the endpoint.
	DNS []string
	// Insecure disables endpoint public key pinning.
	Insecure bool

	// MTU of the throwaway tunnel used for measurement.
	MTU int

	TopN         int
	ProbeGap     time.Duration
	ProbeTimeout time.Duration
	SpeedGap     time.Duration
	ProbeBytes   int64
	URL          string

	// Account is the loaded WARP account; its endpoint and peer key are used.
	Account usqueconfig.Config

	Logger *log.Logger
}

// DefaultOptions returns Options with sane, rate-limit-friendly values.
func DefaultOptions() Options {
	return Options{
		Modes:        []tunnel.Mode{tunnel.ModeQUIC, tunnel.ModeHTTP2},
		TopN:         3,
		ProbeGap:     1500 * time.Millisecond,
		ProbeTimeout: 8 * time.Second,
		SpeedGap:     5 * time.Second,
		ProbeBytes:   4 << 20, // 4 MiB
		URL:          DefaultURL,
	}
}

func (o *Options) applyDefaults() {
	d := DefaultOptions()
	if len(o.Modes) == 0 {
		o.Modes = d.Modes
	}
	if o.TopN <= 0 {
		o.TopN = d.TopN
	}
	if o.ProbeGap <= 0 {
		o.ProbeGap = d.ProbeGap
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = d.ProbeTimeout
	}
	if o.SpeedGap <= 0 {
		o.SpeedGap = d.SpeedGap
	}
	if o.ProbeBytes <= 0 {
		o.ProbeBytes = d.ProbeBytes
	}
	if strings.TrimSpace(o.URL) == "" {
		o.URL = d.URL
	}
}

func (o Options) logf(format string, args ...any) {
	if o.Logger != nil {
		o.Logger.Printf(format, args...)
	}
}

// BuildCandidates assembles the probe pool from the explicit list, the account
// endpoint and an optional CIDR, preserving order and dropping duplicates.
func BuildCandidates(explicit []string, cidr string, account usqueconfig.Config) ([]tunnel.Endpoint, error) {
	var raw []string
	raw = append(raw, explicit...)
	if len(raw) == 0 {
		raw = append(raw, DefaultCandidates...)
	}
	if ep := strings.TrimSpace(account.EndpointV4); ep != "" {
		raw = append(raw, net.JoinHostPort(ep, "443"))
	}
	if ep := strings.TrimSpace(account.EndpointV6); ep != "" {
		raw = append(raw, net.JoinHostPort(ep, "443"))
	}
	if s := strings.TrimSpace(cidr); s != "" {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("无效的扫描网段 %q: %w", s, err)
		}
		if !prefix.Addr().Is4() {
			// 静默忽略 IPv6 网段会让人以为扫过了：直接拒绝更诚实。
			return nil, fmt.Errorf("网段 %q 不是 IPv4（当前仅支持 IPv4 扫描）", s)
		}
		if prefix.Bits() < 24 {
			return nil, fmt.Errorf("网段 %q 过大（至少 /24），会被 Cloudflare 限流", s)
		}
		raw = append(raw, hostsIn(prefix, "443")...)
	}

	out := make([]tunnel.Endpoint, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		ep, err := tunnel.ParseEndpoint(item, 443)
		if err != nil {
			continue
		}
		key := ep.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ep)
	}
	if len(out) == 0 {
		return nil, errors.New("没有可用的候选端点")
	}
	return out, nil
}

// hostsIn expands a prefix into "ip:port" entries. It refuses prefixes larger
// than /24 to keep scans short.
func hostsIn(prefix netip.Prefix, port string) []string {
	bits := prefix.Bits()
	if bits < prefix.Addr().BitLen()-8 {
		// /16 or wider: only take the first /24 to stay bounded.
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()-8)
	}
	if !prefix.Addr().Is4() {
		return nil
	}
	base := prefix.Masked().Addr().As4()
	count := 1 << (prefix.Addr().BitLen() - prefix.Bits())
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ip := net.IPv4(base[0], base[1], base[2], byte(int(base[3])+i)).String()
		out = append(out, ip+":"+port)
	}
	return out
}

// probeResult is an endpoint that completed the handshake stage.
type probeResult struct {
	Endpoint tunnel.Endpoint
	Mode     tunnel.Mode
	Latency  time.Duration
}

// Run executes both stages and returns the measured results, fastest first.
func Run(ctx context.Context, o Options) ([]Result, error) {
	o.applyDefaults()

	candidates, err := BuildCandidates(o.Candidates, o.CIDR, o.Account)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := o.tlsConfig()
	if err != nil {
		return nil, err
	}

	o.logf("端点优选开始：候选 %d 个，模式 %v，SNI %s",
		len(candidates), modeNames(o.Modes), o.SNI)

	survivors := o.probeStage(ctx, candidates, tlsCfg)

	if len(survivors) == 0 {
		return nil, errors.New("没有任何候选端点完成握手；可能是当前网络屏蔽了 MASQUE，换个 SNI 再试")
	}

	o.logf("握手可用 %d 个，进入隧道内测速（Top %d，间隔 %s 以避免限流）...",
		len(survivors), min(o.TopN, len(survivors)), o.SpeedGap)

	results := o.measureStage(ctx, topN(survivors, o.TopN), tlsCfg)

	if len(results) == 0 {
		return nil, errors.New("握手可用但隧道内测速全部失败；等几分钟再试（Cloudflare 可能正在限流）")
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].MBps != results[j].MBps {
			return results[i].MBps > results[j].MBps
		}
		return results[i].Latency < results[j].Latency
	})
	return results, nil
}

func modeNames(modes []tunnel.Mode) []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return out
}

func topN(in []probeResult, n int) []probeResult {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Latency < in[j].Latency })
	if len(in) > n {
		return in[:n]
	}
	return in
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// tlsConfig builds the MASQUE TLS config from the loaded account.
func (o Options) tlsConfig() (*tls.Config, error) {
	// 用传入的 Account 而不是全局 usqueconfig.AppConfig：Options 已经携带了
	// 账号（候选端点与隧道内地址都取自它），密钥也必须来自同一份，否则两者
	// 不一致时握手会以难排查的方式失败。
	privKey, err := o.Account.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("读取设备私钥失败: %w", err)
	}
	peerPub, err := o.Account.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("读取端点公钥失败: %w", err)
	}
	cert, err := warpapi.GenerateSelfSignedCert(privKey)
	if err != nil {
		return nil, err
	}
	return api.PrepareTlsConfig(privKey, peerPub, cert, o.SNI, o.Insecure)
}
