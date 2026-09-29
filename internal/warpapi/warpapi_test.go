package warpapi

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	usqueconfig "github.com/Diniboy1123/usque/config"
)

// testPEM builds a real PEM encoded public key so that buildConfig's
// validation path is exercised faithfully.
func testPEM(t *testing.T) string {
	t.Helper()
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"162.159.198.1:0", "162.159.198.1", false},
		{"162.159.198.1:2408", "162.159.198.1", false},
		{"[2606:4700:103::1]:0", "2606:4700:103::1", false},
		{"2606:4700:103::1", "2606:4700:103::1", false},
		{"", "", true},
		{"not-an-ip", "", true},
		{"162.159.198.1:notaport", "", true},
	}

	for _, tc := range tests {
		got, err := parseEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseEndpoint(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseEndpoint(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildConfig(t *testing.T) {
	privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	data := &accountData{
		ID:    "device-id",
		Token: "token",
		Account: account{
			ID:      "account-id",
			License: "license",
		},
	}
	data.Config.Peers = []peer{{PublicKey: testPEM(t)}}
	data.Config.Peers[0].Endpoint.V4 = "162.159.198.1:0"
	data.Config.Peers[0].Endpoint.V6 = "[2606:4700:103::1]:0"
	data.Config.Interface.Addresses.V4 = "172.16.0.2"
	data.Config.Interface.Addresses.V6 = "2606:4700:110::1"

	cfg, err := buildConfig(privKeyBytes, "token", data)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	if cfg.EndpointV4 != "162.159.198.1" {
		t.Fatalf("EndpointV4 = %q", cfg.EndpointV4)
	}
	if cfg.EndpointV6 != "2606:4700:103::1" {
		t.Fatalf("EndpointV6 = %q", cfg.EndpointV6)
	}
	if cfg.IPv4 != "172.16.0.2" || cfg.IPv6 != "2606:4700:110::1" {
		t.Fatalf("addresses = %q / %q", cfg.IPv4, cfg.IPv6)
	}
	if cfg.ID != "device-id" || cfg.AccessToken != "token" {
		t.Fatalf("identity = %q / %q", cfg.ID, cfg.AccessToken)
	}
	if cfg.EndpointH2V4 != defaultHTTP2EndpointV4 {
		t.Fatalf("EndpointH2V4 = %q, want %q", cfg.EndpointH2V4, defaultHTTP2EndpointV4)
	}

	// The private key must round-trip through the usque config loader.
	if _, err := base64.StdEncoding.DecodeString(cfg.PrivateKey); err != nil {
		t.Fatalf("private key is not base64: %v", err)
	}
}

func TestBuildConfigRejectsIncompleteData(t *testing.T) {
	if _, err := buildConfig([]byte("k"), "t", &accountData{}); err == nil {
		t.Fatal("missing peers must be rejected")
	}
	if _, err := buildConfig([]byte("k"), "t", nil); err == nil {
		t.Fatal("nil account data must be rejected")
	}

	data := &accountData{}
	data.Config.Peers = []peer{{}}
	data.Config.Peers[0].Endpoint.V4 = "162.159.198.1:0"
	data.Config.Peers[0].Endpoint.V6 = "[2606:4700:103::1]:0"
	if _, err := buildConfig([]byte("k"), "t", data); err == nil {
		t.Fatal("missing peer public key must be rejected")
	}

	data.Config.Peers[0].PublicKey = "not a pem"
	if _, err := buildConfig([]byte("k"), "t", data); err == nil {
		t.Fatal("invalid peer public key must be rejected")
	}
}

func TestSaveAccountPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp.json")

	cfg := usqueconfig.Config{ID: "id", AccessToken: "token", EndpointV4: "162.159.198.1"}
	if err := SaveAccount(path, cfg); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("account permissions = %o, want 600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, field := range []string{`"id"`, `"access_token"`, `"endpoint_v4"`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("saved account is missing %s: %s", field, data)
		}
	}
}

func TestAPIErrorMessage(t *testing.T) {
	var err APIError
	err.Errors = append(err.Errors, struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Code: 1001, Message: "rate limited"})

	if !strings.Contains(err.Error(), "1001") || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("unexpected error text: %v", err.Error())
	}
	if !err.HasCode(1001) || err.HasCode(9999) {
		t.Fatal("HasCode did not match the reported code")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cert, err := GenerateSelfSignedCert(key)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	if len(cert) != 1 || len(cert[0]) == 0 {
		t.Fatalf("unexpected certificate: %v", cert)
	}
	if _, err := GenerateSelfSignedCert(nil); err == nil {
		t.Fatal("nil key must be rejected")
	}
}
