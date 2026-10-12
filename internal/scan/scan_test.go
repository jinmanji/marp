package scan

import (
	"net/netip"
	"testing"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"

	"marp/internal/tunnel"
)

func TestBuildCandidatesDefaults(t *testing.T) {
	eps, err := BuildCandidates(nil, "", usqueconfig.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != len(DefaultCandidates) {
		t.Fatalf("default pool: got %d candidates, want %d", len(eps), len(DefaultCandidates))
	}
	if eps[0].String() != DefaultCandidates[0] {
		t.Fatalf("first candidate = %q, want %q", eps[0].String(), DefaultCandidates[0])
	}
}

func TestBuildCandidatesDedupWithAccount(t *testing.T) {
	// 显式列表里同一个端点的两种写法（带/不带 :443）与账号下发的 V4 是同一个，
	// 只应保留一份；账号的 V6 是另一个。
	eps, err := BuildCandidates(
		[]string{"162.159.198.2:443", "162.159.198.2"},
		"",
		usqueconfig.Config{EndpointV4: "162.159.198.2", EndpointV6: "2606:4700:103::"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("dedup: got %d candidates (%v), want 2", len(eps), eps)
	}
	if eps[0].String() != "162.159.198.2:443" {
		t.Fatalf("first = %q", eps[0].String())
	}
	if eps[1].String() != "[2606:4700:103::]:443" {
		t.Fatalf("second = %q", eps[1].String())
	}
}

func TestBuildCandidatesCIDR(t *testing.T) {
	eps, err := BuildCandidates([]string{"198.51.100.9:443"}, "203.0.113.0/24", usqueconfig.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// 1 个显式 + 256 个网段地址（无重叠）。
	if len(eps) != 257 {
		t.Fatalf("cidr expansion: got %d, want 257", len(eps))
	}
}

func TestBuildCandidatesRejects(t *testing.T) {
	cases := []struct {
		name string
		cidr string
	}{
		{"invalid", "banana"},
		{"too wide", "10.0.0.0/16"},
		{"ipv6", "2001:db8::/64"},
	}
	for _, tc := range cases {
		if _, err := BuildCandidates(nil, tc.cidr, usqueconfig.Config{}); err == nil {
			t.Fatalf("%s: expected error for %q", tc.name, tc.cidr)
		}
	}
}

func TestHostsIn(t *testing.T) {
	hosts := hostsIn(netip.MustParsePrefix("192.0.2.0/25"), "443")
	if len(hosts) != 128 {
		t.Fatalf("/25: got %d hosts, want 128", len(hosts))
	}
	if hosts[0] != "192.0.2.0:443" || hosts[127] != "192.0.2.127:443" {
		t.Fatalf("bounds: first=%q last=%q", hosts[0], hosts[127])
	}
}

func TestApplyDefaults(t *testing.T) {
	var o Options
	o.applyDefaults()
	if len(o.Modes) != 2 || o.Modes[0] != tunnel.ModeQUIC || o.Modes[1] != tunnel.ModeHTTP2 {
		t.Fatalf("modes = %v", o.Modes)
	}
	if o.TopN != 3 || o.ProbeGap != 1500*time.Millisecond || o.ProbeTimeout != 8*time.Second ||
		o.SpeedGap != 5*time.Second || o.ProbeBytes != 4<<20 || o.URL != DefaultURL {
		t.Fatalf("defaults = %+v", o)
	}
	// 已显式设置的值不能被覆盖。
	o2 := Options{TopN: 9, ProbeBytes: 123}
	o2.applyDefaults()
	if o2.TopN != 9 || o2.ProbeBytes != 123 {
		t.Fatalf("explicit values overridden: %+v", o2)
	}
}
