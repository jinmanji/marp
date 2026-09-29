package tunnel

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLogs runs fn with a logger writing into buf.
func captureLogs(fn func(opts Options)) string {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	fn(Options{Logger: logger})
	return buf.String()
}

func TestHintFailureNotEnrolled(t *testing.T) {
	out := captureLogs(func(opts Options) {
		opts.SNI = "consumer-masque-proxy.cloudflareclient.com"
		hintFailure(opts, errors.New("login failed! Please double-check if your tls key and cert is enrolled"))
	})
	if !strings.Contains(out, "未通过入网认证") {
		t.Fatalf("expected an enrolment hint, got: %q", out)
	}
	if strings.Contains(out, "并不是可用的 MASQUE 端点") {
		t.Fatalf("enrolment failure must not blame the endpoint: %q", out)
	}
}

func TestHintFailureTLSRejection(t *testing.T) {
	out := captureLogs(func(opts Options) {
		opts.SNI = "consumer-masque-proxy.cloudflareclient.com"
		hintFailure(opts, errors.New("failed to dial connect-ip: CRYPTO_ERROR 0x128 (remote): tls: handshake failure"))
	})
	if !strings.Contains(out, "并不是可用的 MASQUE 端点") {
		t.Fatalf("expected an endpoint hint, got: %q", out)
	}
	// With the real SNI the insecure suggestion is noise.
	if strings.Contains(out, "insecure") {
		t.Fatalf("must not suggest insecure with a Cloudflare SNI: %q", out)
	}
}

func TestHintFailureMasqueradeSNI(t *testing.T) {
	out := captureLogs(func(opts Options) {
		opts.SNI = "recaptcha.net"
		hintFailure(opts, errors.New("CRYPTO_ERROR 0x128 (remote): tls: handshake failure"))
	})
	if !strings.Contains(out, "伪装") || !strings.Contains(out, "insecure") {
		t.Fatalf("expected a masquerade hint mentioning insecure, got: %q", out)
	}

	// Once pinning is already disabled the insecure hint is pointless.
	out = captureLogs(func(opts Options) {
		opts.SNI = "recaptcha.net"
		opts.Insecure = true
		hintFailure(opts, errors.New("CRYPTO_ERROR 0x128 (remote): tls: handshake failure"))
	})
	if strings.Contains(out, "insecure") {
		t.Fatalf("must not suggest insecure when already disabled: %q", out)
	}
}

func TestHintFailurePublicKeyMismatch(t *testing.T) {
	out := captureLogs(func(opts Options) {
		opts.SNI = "consumer-masque-proxy.cloudflareclient.com"
		hintFailure(opts, errors.New("remote endpoint has a different public key than what we trust"))
	})
	if !strings.Contains(out, "公钥与账号记录不符") {
		t.Fatalf("expected a pinning hint, got: %q", out)
	}

	out = captureLogs(func(opts Options) {
		opts.Insecure = true
		hintFailure(opts, errors.New("remote endpoint has a different public key than what we trust"))
	})
	if out != "" {
		t.Fatalf("pinning hints are pointless when insecure, got: %q", out)
	}
}

func TestHintFailureNilError(t *testing.T) {
	if out := captureLogs(func(opts Options) { hintFailure(opts, nil) }); out != "" {
		t.Fatalf("nil error must be silent, got: %q", out)
	}
}

func TestOptionsApplyDefaults(t *testing.T) {
	var opts Options
	opts.applyDefaults()

	if opts.Mode != ModeAuto {
		t.Fatalf("Mode = %q, want %q", opts.Mode, ModeAuto)
	}
	if opts.MTU != 1280 {
		t.Fatalf("MTU = %d, want 1280", opts.MTU)
	}
	if opts.ReconnectDelay != time.Second {
		t.Fatalf("ReconnectDelay = %v, want 1s", opts.ReconnectDelay)
	}
	if opts.ConnectTimeout != 15*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 15s", opts.ConnectTimeout)
	}
	if opts.QUICFailureThreshold != 3 {
		t.Fatalf("QUICFailureThreshold = %d, want 3", opts.QUICFailureThreshold)
	}
	if opts.H2RetryInterval != 5*time.Minute {
		t.Fatalf("H2RetryInterval = %v, want 5m", opts.H2RetryInterval)
	}
	if opts.QUICConfig == nil || !opts.QUICConfig.EnableDatagrams {
		t.Fatal("Connect-IP needs QUIC datagrams enabled")
	}
}

func TestDefaultQUICConfigPinnedPacketSize(t *testing.T) {
	cfg := DefaultQUICConfig(30*time.Second, 1400)
	if cfg.InitialPacketSize != 1400 {
		t.Fatalf("InitialPacketSize = %d, want 1400", cfg.InitialPacketSize)
	}
	if !cfg.DisablePathMTUDiscovery {
		t.Fatal("pinned packet size must disable PMTU discovery")
	}

	auto := DefaultQUICConfig(30*time.Second, 0)
	if auto.InitialPacketSize != 0 || auto.DisablePathMTUDiscovery {
		t.Fatal("packet size 0 must keep PMTU discovery enabled")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":      ModeAuto,
		"auto":  ModeAuto,
		"quic":  ModeQUIC,
		"http2": ModeHTTP2,
	}
	for in, want := range cases {
		opts := Options{Mode: Mode(in)}
		opts.applyDefaults()
		if opts.Mode != want {
			t.Fatalf("mode %q -> %q, want %q", in, opts.Mode, want)
		}
	}
}
