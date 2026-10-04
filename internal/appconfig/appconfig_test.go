package appconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCreatesConfigWithRandomCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg, created, err := Load(path, Overrides{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !created {
		t.Fatal("Load reported created=false on a fresh directory")
	}
	if !cfg.Auth.Required() {
		t.Fatal("authentication should be enabled by default")
	}
	if len(cfg.Auth.Username) != 10 {
		t.Fatalf("username length = %d, want 10", len(cfg.Auth.Username))
	}
	if len(cfg.Auth.Password) != 20 {
		t.Fatalf("password length = %d, want 20", len(cfg.Auth.Password))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config permissions = %o, want 600", perm)
	}

	// A second run must reuse the persisted credentials.
	again, created, err := Load(path, Overrides{})
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if created {
		t.Fatal("second Load must not recreate the config")
	}
	if again.Auth.Username != cfg.Auth.Username || again.Auth.Password != cfg.Auth.Password {
		t.Fatal("credentials changed between runs")
	}
}

func TestLoadGeneratesDistinctCredentials(t *testing.T) {
	dir := t.TempDir()

	first, _, err := Load(filepath.Join(dir, "a.json"), Overrides{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	second, _, err := Load(filepath.Join(dir, "b.json"), Overrides{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if first.Auth.Username == second.Auth.Username || first.Auth.Password == second.Auth.Password {
		t.Fatal("random credentials collided across configs")
	}
}

func TestLoadFillsMissingCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	raw := `{"listen":{"socks5":"0.0.0.0:1080"},"auth":{"enabled":true}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, created, err := Load(path, Overrides{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if created {
		t.Fatal("existing file must not be reported as created")
	}
	if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
		t.Fatal("missing credentials were not generated")
	}
	if cfg.Listen.HTTP != defaultHTTPAddr {
		t.Fatalf("listen.http = %q, want %q", cfg.Listen.HTTP, defaultHTTPAddr)
	}
	if cfg.Tunnel.SNI != defaultSNI {
		t.Fatalf("tunnel.sni = %q, want %q", cfg.Tunnel.SNI, defaultSNI)
	}
	if cfg.Tunnel.Mode != defaultMode {
		t.Fatalf("tunnel.mode = %q, want %q", cfg.Tunnel.Mode, defaultMode)
	}
	if cfg.Tunnel.MTU != 1280 {
		t.Fatalf("tunnel.mtu = %d, want 1280", cfg.Tunnel.MTU)
	}

	// The filled-in values must have been written back.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var onDisk Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if onDisk.Auth.Password != cfg.Auth.Password {
		t.Fatal("generated password was not persisted")
	}
}

func TestAuthDisabledStaysDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	raw := `{"auth":{"enabled":false}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := Load(path, Overrides{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Username != "" || cfg.Auth.Password != "" {
		t.Fatal("credentials must not be generated when auth is disabled")
	}
	if cfg.Auth.Required() {
		t.Fatal("auth must stay disabled")
	}
}

func TestAccountPath(t *testing.T) {
	cfg := Default()
	cfg.Warp.ConfigFile = "account.json"

	got := cfg.AccountPath(filepath.Join("/etc", "warp-proxy", "config.json"))
	want := filepath.Join("/etc", "warp-proxy", "account.json")
	if got != want {
		t.Fatalf("AccountPath = %q, want %q", got, want)
	}

	cfg.Warp.ConfigFile = "/absolute/warp.json"
	if got := cfg.AccountPath("relative/config.json"); got != "/absolute/warp.json" {
		t.Fatalf("absolute AccountPath = %q", got)
	}
}

func TestDurationHelpersFallBack(t *testing.T) {
	var t1 Tunnel
	if got := t1.KeepaliveDuration(); got.Seconds() != 30 {
		t.Fatalf("KeepaliveDuration = %v, want 30s", got)
	}
	if got := t1.H2RetryIntervalDuration(); got.Minutes() != 5 {
		t.Fatalf("H2RetryIntervalDuration = %v, want 5m", got)
	}
	if got := t1.ConnectTimeoutDuration(); got.Seconds() != 15 {
		t.Fatalf("ConnectTimeoutDuration = %v, want 15s", got)
	}

	t1.Keepalive = "45s"
	if got := t1.KeepaliveDuration(); got.String() != "45s" {
		t.Fatalf("KeepaliveDuration = %v, want 45s", got)
	}
	t1.Keepalive = "not-a-duration"
	if got := t1.KeepaliveDuration(); got.Seconds() != 30 {
		t.Fatalf("invalid duration should fall back, got %v", got)
	}
}

func TestDefaultPathUsesHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvConfigPath, "")
	t.Setenv("HOME", home)

	got, warning := DefaultPath()
	want := filepath.Join(home, DefaultDirName, "config.json")
	if got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
	if warning != "" {
		t.Fatalf("unexpected warning: %q", warning)
	}
	if strings.Contains(got, home+"/.marp/../") {
		t.Fatalf("path was not cleaned: %q", got)
	}
}

func TestDefaultPathHonoursEnv(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "elsewhere.json")
	t.Setenv(EnvConfigPath, custom)

	got, warning := DefaultPath()
	if got != custom {
		t.Fatalf("DefaultPath = %q, want %q (from $%s)", got, custom, EnvConfigPath)
	}
	if warning != "" {
		t.Fatalf("unexpected warning: %q", warning)
	}
}

func TestDefaultPathFallsBackWithoutHome(t *testing.T) {
	t.Setenv(EnvConfigPath, "")
	t.Setenv("HOME", "")

	got, warning := DefaultPath()
	// On some platforms UserHomeDir still resolves (Android falls back to
	// /sdcard); only assert the fallback when it really failed.
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		if got != filepath.Join(home, DefaultDirName, "config.json") {
			t.Fatalf("DefaultPath = %q, want a path under %q", got, home)
		}
		return
	}
	if got != "config.json" {
		t.Fatalf("DefaultPath fallback = %q, want config.json", got)
	}
	if warning == "" {
		t.Fatal("fallback must come with a warning")
	}
	if !strings.Contains(warning, EnvConfigPath) {
		t.Fatalf("warning should mention %s, got %q", EnvConfigPath, warning)
	}
}

// New file + -sni: the requested SNI must be recorded in the file itself.
func TestLoadBakesOverridesIntoNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg, created, err := Load(path, Overrides{
		SNI:       "recaptcha.net",
		Mode:      "HTTP2",
		Endpoints: []string{"162.159.198.218:443", "162.159.198.5:443"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !created {
		t.Fatal("expected the file to be created")
	}
	if cfg.Tunnel.SNI != "recaptcha.net" {
		t.Fatalf("returned SNI = %q", cfg.Tunnel.SNI)
	}
	if cfg.Tunnel.Mode != "http2" {
		t.Fatalf("Mode should be lower-cased, got %q", cfg.Tunnel.Mode)
	}

	// Re-read from disk: the overrides must have been persisted.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var onDisk Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if onDisk.Tunnel.SNI != "recaptcha.net" {
		t.Fatalf("on-disk SNI = %q, want recaptcha.net", onDisk.Tunnel.SNI)
	}
	if onDisk.Tunnel.Mode != "http2" {
		t.Fatalf("on-disk mode = %q, want http2", onDisk.Tunnel.Mode)
	}
	if len(onDisk.Tunnel.Endpoints) != 2 {
		t.Fatalf("on-disk endpoints = %v", onDisk.Tunnel.Endpoints)
	}
}

// Existing file + -sni: the flag wins at runtime but must not rewrite the file.
func TestLoadOverrideDoesNotRewriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Seed a config whose SNI is the default.
	if _, _, err := Load(path, Overrides{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	cfg, created, err := Load(path, Overrides{SNI: "recaptcha.net"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if created {
		t.Fatal("existing file must not be reported as created")
	}
	if cfg.Tunnel.SNI != "recaptcha.net" {
		t.Fatalf("override must win at runtime, SNI = %q", cfg.Tunnel.SNI)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("file on disk was modified:\nbefore: %s\nafter:  %s", before, after)
	}
	var onDisk Config
	if err := json.Unmarshal(after, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if onDisk.Tunnel.SNI == "recaptcha.net" {
		t.Fatal("override leaked into the file; it should stay runtime-only")
	}
	if onDisk.Tunnel.SNI != defaultSNI {
		t.Fatalf("on-disk SNI should still be %q, got %q", defaultSNI, onDisk.Tunnel.SNI)
	}
}

func TestOverridesIsZero(t *testing.T) {
	if !(Overrides{}).IsZero() {
		t.Fatal("empty overrides must report IsZero")
	}
	if (Overrides{SNI: "   "}).IsZero() != true {
		t.Fatal("blank SNI must count as zero")
	}
	if (Overrides{SNI: "a"}).IsZero() {
		t.Fatal("SNI must not count as zero")
	}
	if (Overrides{Mode: "quic"}).IsZero() {
		t.Fatal("mode must not count as zero")
	}
	if (Overrides{Endpoints: []string{"1.2.3.4:443"}}).IsZero() {
		t.Fatal("endpoints must not count as zero")
	}
}

func TestAccountPathResolvesNextToConfig(t *testing.T) {
	cfg := Default()
	got := cfg.AccountPath(filepath.Join("/home", "bob", ".marp", "config.json"))
	want := filepath.Join("/home", "bob", ".marp", "warp.json")
	if got != want {
		t.Fatalf("AccountPath = %q, want %q", got, want)
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := Load(path, Overrides{}); err == nil {
		t.Fatal("invalid JSON should produce an error")
	} else if !strings.Contains(err.Error(), "解析配置文件") {
		t.Fatalf("unexpected error: %v", err)
	}
}
