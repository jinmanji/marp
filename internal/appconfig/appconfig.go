// Package appconfig handles loading, defaulting and persisting the local
// application configuration (proxy listeners, credentials, WARP account and
// tunnel tuning).
//
// The configuration file is optional: when it is missing a fully populated
// configuration is generated in memory, random proxy credentials are assigned
// and the result is written back to disk so that the same credentials keep
// working across restarts.
package appconfig

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// FilePerm is used for the configuration file. Credentials are stored in
	// plain text, so the file is kept owner-readable only.
	FilePerm fs.FileMode = 0o600

	defaultSocksAddr = "127.0.0.1:1080"
	defaultHTTPAddr  = "127.0.0.1:8000"

	defaultAccountFile = "warp.json"
	defaultSNI         = "consumer-masque-proxy.cloudflareclient.com"
	defaultMode        = "auto"
)

// Auth holds the proxy credentials presented by both the HTTP and the SOCKS5
// listeners.
type Auth struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Required reports whether authentication must be enforced.
func (a Auth) Required() bool {
	return a.Enabled && a.Username != "" && a.Password != ""
}

// Listen describes the two local proxy listeners.
type Listen struct {
	Socks5 string `json:"socks5"`
	HTTP   string `json:"http"`
}

// Warp holds everything needed to register and persist a WARP account.
type Warp struct {
	// ConfigFile is where the WARP account (private key, token, endpoints)
	// is stored. A relative path is resolved against the directory holding
	// the application configuration.
	ConfigFile string `json:"config_file"`
	// AutoRegister triggers registration when the account file is missing.
	AutoRegister bool `json:"auto_register"`
	// AcceptTOS records the user's acceptance of the Cloudflare terms.
	AcceptTOS  bool   `json:"accept_tos"`
	DeviceName string `json:"device_name"`
	Model      string `json:"model"`
	Locale     string `json:"locale"`
	// TeamToken is a Zero Trust team token. Empty means a free account.
	TeamToken string `json:"team_token"`
}

// Tunnel holds the MASQUE transport settings.
type Tunnel struct {
	// Endpoints is the "ip:port" pool used to reach Cloudflare. Entries may
	// omit the port, in which case Port is used. When empty the endpoints
	// stored in the WARP account are used.
	Endpoints []string `json:"endpoints"`
	// SNI is the TLS server name. It can be swapped for a masquerade domain
	// (for example "recaptcha.net") to disguise the tunnel.
	SNI string `json:"sni"`
	// Mode selects the transport: auto (QUIC first with HTTP/2 fallback),
	// quic or http2.
	Mode string `json:"mode"`
	// Port is the default port for endpoints that do not specify one.
	Port    int  `json:"port"`
	UseIPv6 bool `json:"use_ipv6"`

	Keepalive string `json:"keepalive"`
	// DNS servers used inside the tunnel; their queries travel through WARP.
	DNS        []string `json:"dns"`
	DNSTimeout string   `json:"dns_timeout"`
	// MTU of the userspace tunnel. 1280 is the only well tested value.
	MTU int `json:"mtu"`

	ReconnectDelay string `json:"reconnect_delay"`
	ConnectTimeout string `json:"connect_timeout"`
	// QUICFailureThreshold is how many consecutive QUIC failures are tolerated
	// before the HTTP/2 fallback kicks in.
	QUICFailureThreshold int `json:"quic_failure_threshold"`
	// H2RetryInterval is how long HTTP/2 is used before QUIC is probed again.
	H2RetryInterval string `json:"h2_retry_interval"`
	// InitialPacketSize pins the QUIC initial packet size; 0 uses PMTU
	// discovery.
	InitialPacketSize uint16 `json:"initial_packet_size"`
	// Insecure disables endpoint public key pinning.
	Insecure bool `json:"insecure"`
}

// Config is the complete on-disk configuration.
type Config struct {
	Listen    Listen `json:"listen"`
	Auth      Auth   `json:"auth"`
	Warp      Warp   `json:"warp"`
	Tunnel    Tunnel `json:"tunnel"`
	CreatedAt string `json:"created_at"`
}

// Default returns the configuration used when no file exists yet.
func Default() Config {
	return Config{
		Listen: Listen{
			Socks5: defaultSocksAddr,
			HTTP:   defaultHTTPAddr,
		},
		Auth: Auth{Enabled: true},
		Warp: Warp{
			ConfigFile:   defaultAccountFile,
			AutoRegister: true,
			AcceptTOS:    true,
			DeviceName:   "warp-masque-proxy",
			Model:        "PC",
			Locale:       "en_US",
		},
		Tunnel: Tunnel{
			Endpoints:            []string{},
			SNI:                  defaultSNI,
			Mode:                 defaultMode,
			Port:                 443,
			Keepalive:            "30s",
			DNS:                  []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
			DNSTimeout:           "5s",
			MTU:                  1280,
			ReconnectDelay:       "1s",
			ConnectTimeout:       "15s",
			QUICFailureThreshold: 3,
			H2RetryInterval:      "5m",
		},
	}
}

// Load reads the configuration from path. When the file does not exist a
// default configuration with freshly generated random credentials is returned
// and persisted. The second return value reports whether the file was created
// by this call.
func Load(path string) (cfg Config, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, false, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
		merged, changed := applyDefaults(cfg)
		cfg = merged
		if changed {
			if err := Save(path, cfg); err != nil {
				return cfg, false, err
			}
		}
		return cfg, false, nil
	case errors.Is(err, fs.ErrNotExist):
		// First run: build a complete configuration from scratch.
	default:
		return cfg, false, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}

	cfg = Default()
	username, err := randomString(10, lowerLetters)
	if err != nil {
		return cfg, false, err
	}
	password, err := randomString(20, lowerLetters+upperLetters+digits)
	if err != nil {
		return cfg, false, err
	}
	cfg.Auth.Username = username
	cfg.Auth.Password = password
	cfg.CreatedAt = time.Now().Format(time.RFC3339)

	if err := Save(path, cfg); err != nil {
		return cfg, false, err
	}
	return cfg, true, nil
}

// Save writes cfg to path with owner-only permissions.
func Save(path string, cfg Config) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建配置目录 %s 失败: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, FilePerm); err != nil {
		return fmt.Errorf("写入配置 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("保存配置 %s 失败: %w", path, err)
	}
	return os.Chmod(path, FilePerm)
}

// applyDefaults fills in every field the user left empty and generates random
// credentials when authentication is enabled but no credentials exist yet.
// It reports whether anything had to be filled in.
func applyDefaults(in Config) (Config, bool) {
	out := in
	changed := false

	setIfEmpty := func(dst *string, value string) {
		if strings.TrimSpace(*dst) == "" {
			*dst = value
			changed = true
		}
	}

	setIfEmpty(&out.Listen.Socks5, defaultSocksAddr)
	setIfEmpty(&out.Listen.HTTP, defaultHTTPAddr)
	setIfEmpty(&out.Warp.ConfigFile, defaultAccountFile)
	setIfEmpty(&out.Warp.Model, "PC")
	setIfEmpty(&out.Warp.Locale, "en_US")
	setIfEmpty(&out.Tunnel.SNI, defaultSNI)
	setIfEmpty(&out.Tunnel.Mode, defaultMode)
	setIfEmpty(&out.Tunnel.Keepalive, "30s")
	setIfEmpty(&out.Tunnel.DNSTimeout, "5s")
	setIfEmpty(&out.Tunnel.ReconnectDelay, "1s")
	setIfEmpty(&out.Tunnel.ConnectTimeout, "15s")
	setIfEmpty(&out.Tunnel.H2RetryInterval, "5m")

	if out.Tunnel.Port <= 0 || out.Tunnel.Port > 65535 {
		out.Tunnel.Port = 443
		changed = true
	}
	if out.Tunnel.MTU <= 0 {
		out.Tunnel.MTU = 1280
		changed = true
	}
	if out.Tunnel.QUICFailureThreshold <= 0 {
		out.Tunnel.QUICFailureThreshold = 3
		changed = true
	}
	if len(out.Tunnel.DNS) == 0 {
		out.Tunnel.DNS = Default().Tunnel.DNS
		changed = true
	}

	if out.Auth.Required() {
		return out, changed
	}

	// Authentication requested but incomplete, or switched on without
	// credentials: mint a fresh random pair so the listeners are never
	// exposed unauthenticated by accident.
	if out.Auth.Enabled {
		if username, err := randomString(10, lowerLetters); err == nil {
			out.Auth.Username = username
			changed = true
		}
		if password, err := randomString(20, lowerLetters+upperLetters+digits); err == nil {
			out.Auth.Password = password
			changed = true
		}
	}

	return out, changed
}

// AccountPath resolves the WARP account file path relative to the directory
// holding the application configuration.
func (c Config) AccountPath(configPath string) string {
	name := c.Warp.ConfigFile
	if name == "" {
		name = defaultAccountFile
	}
	if filepath.IsAbs(name) {
		return name
	}
	dir := filepath.Dir(configPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, name)
}

// KeepaliveDuration parses Tunnel.Keepalive.
func (t Tunnel) KeepaliveDuration() time.Duration { return parseDuration(t.Keepalive, 30*time.Second) }

// DNSTimeoutDuration parses Tunnel.DNSTimeout.
func (t Tunnel) DNSTimeoutDuration() time.Duration { return parseDuration(t.DNSTimeout, 5*time.Second) }

// ReconnectDelayDuration parses Tunnel.ReconnectDelay.
func (t Tunnel) ReconnectDelayDuration() time.Duration {
	return parseDuration(t.ReconnectDelay, time.Second)
}

// ConnectTimeoutDuration parses Tunnel.ConnectTimeout.
func (t Tunnel) ConnectTimeoutDuration() time.Duration {
	return parseDuration(t.ConnectTimeout, 15*time.Second)
}

// H2RetryIntervalDuration parses Tunnel.H2RetryInterval.
func (t Tunnel) H2RetryIntervalDuration() time.Duration {
	return parseDuration(t.H2RetryInterval, 5*time.Minute)
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits       = "0123456789"
)

// randomString returns a cryptographically random string of n characters
// drawn from charset.
func randomString(n int, charset string) (string, error) {
	if n <= 0 || charset == "" {
		return "", errors.New("invalid random string parameters")
	}
	out := make([]byte, n)
	limit := big.NewInt(int64(len(charset)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("生成随机凭据失败: %w", err)
		}
		out[i] = charset[idx.Int64()]
	}
	return string(out), nil
}
