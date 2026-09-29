package tunnel

import "testing"

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		port    int
		want    string
		wantErr bool
	}{
		{"ipv4 with port", "162.159.198.218:443", 443, "162.159.198.218:443", false},
		{"ipv4 without port", "162.159.198.218", 8443, "162.159.198.218:8443", false},
		{"ipv6 bracketed", "[2606:4700:103::1]:443", 443, "[2606:4700:103::1]:443", false},
		{"ipv6 bare", "2606:4700:103::1", 443, "[2606:4700:103::1]:443", false},
		{"custom port", "162.159.198.20:5000", 443, "162.159.198.20:5000", false},
		{"empty", "", 443, "", true},
		{"hostname", "example.com:443", 443, "", true},
		{"bad port", "162.159.198.1:0", 443, "", true},
		{"bad port range", "162.159.198.1:70000", 443, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEndpoint(tc.input, tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseEndpoint(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEndpoint(%q) unexpected error: %v", tc.input, err)
			}
			if got.String() != tc.want {
				t.Fatalf("ParseEndpoint(%q) = %q, want %q", tc.input, got.String(), tc.want)
			}
		})
	}
}

func TestParseEndpoints(t *testing.T) {
	got, err := ParseEndpoints([]string{
		"162.159.198.218:443",
		"162.159.198.20:443, 162.159.198.5:443",
		"",
		"162.159.198.218:443", // duplicate, must be dropped
	}, 443)
	if err != nil {
		t.Fatalf("ParseEndpoints unexpected error: %v", err)
	}
	want := []string{"162.159.198.218:443", "162.159.198.20:443", "162.159.198.5:443"}
	if len(got) != len(want) {
		t.Fatalf("got %d endpoints, want %d: %v", len(got), len(want), JoinEndpoints(got))
	}
	for i, ep := range got {
		if ep.String() != want[i] {
			t.Fatalf("endpoint %d = %q, want %q", i, ep.String(), want[i])
		}
	}
}

func TestParseEndpointsEmpty(t *testing.T) {
	if _, err := ParseEndpoints([]string{"  ", ""}, 443); err == nil {
		t.Fatal("ParseEndpoints on an empty list should fail")
	}
}

func TestEndpointAddrHelpers(t *testing.T) {
	ep, err := ParseEndpoint("162.159.198.218:8443", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.IsIPv6() {
		t.Fatal("IPv4 endpoint reported as IPv6")
	}
	if got := ep.UDPAddr().String(); got != "162.159.198.218:8443" {
		t.Fatalf("UDPAddr = %q", got)
	}
	if got := ep.TCPAddr().String(); got != "162.159.198.218:8443" {
		t.Fatalf("TCPAddr = %q", got)
	}
}

func TestIsCloudflareSNI(t *testing.T) {
	if !IsCloudflareSNI("consumer-masque-proxy.cloudflareclient.com") {
		t.Fatal("Cloudflare SNI not recognised")
	}
	if IsCloudflareSNI("recaptcha.net") {
		t.Fatal("masquerade SNI wrongly reported as Cloudflare")
	}
	if IsCloudflareSNI("") {
		t.Fatal("empty SNI wrongly reported as Cloudflare")
	}
}

func TestJoinEndpoints(t *testing.T) {
	got := JoinEndpoints([]Endpoint{
		{IP: parseIP(t, "162.159.198.1"), Port: 443},
		{IP: parseIP(t, "162.159.198.2"), Port: 443},
	})
	want := "162.159.198.1:443, 162.159.198.2:443"
	if got != want {
		t.Fatalf("JoinEndpoints = %q, want %q", got, want)
	}
}
