// Package warpapi implements Cloudflare WARP account registration and the
// extraction of the MASQUE tunnel configuration.
//
// The flow mirrors what wgcf does for WireGuard accounts: a device is
// registered against the WARP client API, the account (license, tunnel
// addresses, peer public key and MASQUE endpoints) is fetched from the same
// response payload and finally persisted to disk. The only difference is that
// the enrolled key is a P-256 key used for the MASQUE handshake instead of a
// Curve25519 WireGuard key.
package warpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	usqueconfig "github.com/Diniboy1123/usque/config"
)

const (
	// BaseURL is the WARP client API endpoint.
	BaseURL = "https://api.cloudflareclient.com"
	// Version is the client API version the official Android app reports.
	Version = "v0a4471"

	defaultModel  = "PC"
	defaultLocale = "en_US"

	keyTypeMASQUE = "secp256r1"
	tunnelMASQUE  = "masque"

	// defaultHTTP2EndpointV4 is used only for the TCP/HTTP2 fallback mode.
	defaultHTTP2EndpointV4 = "162.159.198.2"
)

// Headers sent with every API call. They mirror the official WARP client so
// that Cloudflare answers with the regular (non-ZeroTrust) payload.
var headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}

// APIError is a structured error returned by the WARP API.
type APIError struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Messages []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"messages"`
}

func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("WARP API 错误 %d: %s", e.Errors[0].Code, e.Errors[0].Message)
	}
	if len(e.Messages) > 0 {
		return fmt.Sprintf("WARP API 错误 %d: %s", e.Messages[0].Code, e.Messages[0].Message)
	}
	return "WARP API 返回错误"
}

// HasCode reports whether the API rejected the request with the given code.
func (e *APIError) HasCode(code int) bool {
	for _, item := range e.Errors {
		if item.Code == code {
			return true
		}
	}
	for _, item := range e.Messages {
		if item.Code == code {
			return true
		}
	}
	return false
}

// registration is the registration request body (the "device" payload).
type registration struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

// deviceUpdate is the body of the key enrollment request.
type deviceUpdate struct {
	Key     string `json:"key"`
	Name    string `json:"name,omitempty"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
}

// accountData is the subset of the API payload needed to build the tunnel
// configuration.
type accountData struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Model   string  `json:"model"`
	Key     string  `json:"key"`
	Token   string  `json:"token"`
	Account account `json:"account"`
	Config  config  `json:"config"`
	Policy  policy  `json:"policy"`
}

type account struct {
	ID          string `json:"id"`
	AccountType string `json:"account_type"`
	License     string `json:"license"`
	WarpPlus    bool   `json:"warp_plus"`
	Quota       int    `json:"quota"`
}

type config struct {
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []peer `json:"peers"`
}

type peer struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4    string `json:"v4"`
		V6    string `json:"v6"`
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"endpoint"`
}

type policy struct {
	TunnelProtocol string `json:"tunnel_protocol"`
}

// Client talks to the WARP client API.
type Client struct {
	HTTP       *http.Client
	BaseURL    string
	TeamToken  string
	Model      string
	Locale     string
	DeviceName string
}

// NewClient builds a client with sane defaults and a 30 second timeout.
func NewClient(teamToken, model, locale, deviceName string) *Client {
	if model == "" {
		model = defaultModel
	}
	if locale == "" {
		locale = defaultLocale
	}
	return &Client{
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		BaseURL:    BaseURL,
		TeamToken:  teamToken,
		Model:      model,
		Locale:     locale,
		DeviceName: deviceName,
	}
}

func (c *Client) do(ctx context.Context, method, path, token string, payload any) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("序列化请求失败: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/"+Version+path, body)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if c.TeamToken != "" && path == "/reg" {
		req.Header.Set("CF-Access-Jwt-Assertion", c.TeamToken)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 WARP API 失败: %w", err)
	}
	return resp, nil
}

// decode reads the response body, turning API errors into *APIError.
func decode(resp *http.Response, out any) error {
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if err := json.Unmarshal(data, &apiErr); err != nil {
			return fmt.Errorf("WARP API 返回 HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
		}
		return &apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	return nil
}

// RegisterDevice creates a brand new WARP account. The returned payload holds
// the device id, the API token and (for existing accounts) the tunnel config.
func (c *Client) RegisterDevice(ctx context.Context) (*accountData, error) {
	// A throw-away WireGuard key: the official app always sends one, but we
	// never use it since the account is switched to MASQUE right after.
	wgKey := make([]byte, 32)
	if _, err := rand.Read(wgKey); err != nil {
		return nil, fmt.Errorf("生成临时密钥失败: %w", err)
	}
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("生成设备序列号失败: %w", err)
	}

	payload := registration{
		Key:     base64.StdEncoding.EncodeToString(wgKey),
		Tos:     time.Now().Format("2006-01-02T15:04:05.000-07:00"),
		Model:   c.Model,
		Serial:  hex.EncodeToString(serial),
		KeyType: keyTypeMASQUE,
		TunType: tunnelMASQUE,
		Locale:  c.Locale,
	}

	resp, err := c.do(ctx, http.MethodPost, "/reg", "", payload)
	if err != nil {
		return nil, err
	}
	var data accountData
	if err := decode(resp, &data); err != nil {
		return nil, err
	}
	if data.ID == "" || data.Token == "" {
		return nil, errors.New("注册响应缺少设备 id 或 token")
	}
	return &data, nil
}

// EnrollKey uploads the MASQUE public key and returns the updated account
// data, which is where the tunnel endpoints live.
func (c *Client) EnrollKey(ctx context.Context, deviceID, token string, pubKey []byte) (*accountData, error) {
	if len(pubKey) == 0 {
		return nil, errors.New("公钥为空")
	}
	payload := deviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		Name:    c.DeviceName,
		KeyType: keyTypeMASQUE,
		TunType: tunnelMASQUE,
	}

	resp, err := c.do(ctx, http.MethodPatch, "/reg/"+deviceID, token, payload)
	if err != nil {
		return nil, err
	}
	var data accountData
	if err := decode(resp, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// UpdateLicense binds a WARP+ license to the device.
func (c *Client) UpdateLicense(ctx context.Context, deviceID, token, license string) error {
	payload := map[string]string{"license": license}
	resp, err := c.do(ctx, http.MethodPut, "/reg/"+deviceID+"/account", token, payload)
	if err != nil {
		return err
	}
	return decode(resp, nil)
}

// RegisterOptions configures a registration run.
type RegisterOptions struct {
	Model      string
	Locale     string
	DeviceName string
	TeamToken  string
	License    string
}

// Register runs the full wgcf-style flow: create the account, generate a P-256
// key pair, enroll the key, pull the account down again (to pick up the
// license) and return the resulting configuration.
func Register(ctx context.Context, opts RegisterOptions) (usqueconfig.Config, error) {
	client := NewClient(opts.TeamToken, opts.Model, opts.Locale, opts.DeviceName)

	account, err := client.RegisterDevice(ctx)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("注册 WARP 账号失败: %w", err)
	}

	privKey, err := GenerateKeyPair()
	if err != nil {
		return usqueconfig.Config{}, err
	}
	pubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("序列化公钥失败: %w", err)
	}

	updated, err := client.EnrollKey(ctx, account.ID, account.Token, pubKey)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("注册 MASQUE 设备密钥失败: %w", err)
	}

	// Fetching the account again also refreshes the assigned addresses, which
	// can change for ZeroTrust accounts.
	if opts.License != "" {
		if err := client.UpdateLicense(ctx, account.ID, account.Token, opts.License); err != nil {
			return usqueconfig.Config{}, fmt.Errorf("绑定 WARP+ 许可证失败: %w", err)
		}
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("序列化私钥失败: %w", err)
	}

	cfg, err := buildConfig(privKeyBytes, account.Token, updated)
	if err != nil {
		return usqueconfig.Config{}, err
	}
	return cfg, nil
}

// buildConfig converts the API payload into the on-disk account structure. It
// intentionally matches usque's config.json layout so the file can be shared
// with the upstream tool.
func buildConfig(privKeyBytes []byte, token string, data *accountData) (usqueconfig.Config, error) {
	if data == nil || len(data.Config.Peers) == 0 {
		return usqueconfig.Config{}, errors.New("账号数据缺少对端配置")
	}
	peer := data.Config.Peers[0]

	endpointV4, err := parseEndpoint(peer.Endpoint.V4)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("解析 IPv4 端点失败: %w", err)
	}
	endpointV6, err := parseEndpoint(peer.Endpoint.V6)
	if err != nil {
		return usqueconfig.Config{}, fmt.Errorf("解析 IPv6 端点失败: %w", err)
	}
	if peer.PublicKey == "" {
		return usqueconfig.Config{}, errors.New("账号数据缺少对端公钥")
	}
	// pem.Decode reports malformed input with a nil block, not an error.
	if block, _ := pem.Decode([]byte(peer.PublicKey)); block == nil {
		return usqueconfig.Config{}, errors.New("对端公钥不是合法的 PEM")
	}

	return usqueconfig.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKeyBytes),
		EndpointV4:     endpointV4,
		EndpointV6:     endpointV6,
		EndpointH2V4:   defaultHTTP2EndpointV4,
		EndpointH2V6:   "",
		EndpointPubKey: peer.PublicKey,
		ID:             data.ID,
		AccessToken:    token,
		IPv4:           data.Config.Interface.Addresses.V4,
		IPv6:           data.Config.Interface.Addresses.V6,
	}, nil
}

// parseEndpoint turns "162.159.198.1:0" or "[2606:4700:103::1]:0" into a bare
// IP address.
func parseEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("端点为空")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if _, perr := strconv.Atoi(port); perr != nil {
			return "", fmt.Errorf("端点 %q 的端口无效", value)
		}
		value = host
	}
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if net.ParseIP(value) == nil {
		return "", fmt.Errorf("无效的 IP 地址 %q", value)
	}
	return value, nil
}

// GenerateKeyPair creates the P-256 key pair used for the MASQUE handshake.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ECDSA 密钥失败: %w", err)
	}
	return key, nil
}

// GenerateSelfSignedCert creates the short-lived client certificate presented
// during the MASQUE TLS handshake.
func GenerateSelfSignedCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	if privKey == nil {
		return nil, errors.New("缺少私钥")
	}
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("生成客户端证书失败: %w", err)
	}
	return [][]byte{cert}, nil
}

// SaveAccount persists the account configuration with owner-only permissions.
func SaveAccount(path string, cfg usqueconfig.Config) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建账号目录 %s 失败: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化账号配置失败: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入账号配置 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("保存账号配置 %s 失败: %w", path, err)
	}
	return os.Chmod(path, 0o600)
}

// RegisterAndSave performs registration and stores the result at path.
func RegisterAndSave(ctx context.Context, path string, opts RegisterOptions) error {
	cfg, err := Register(ctx, opts)
	if err != nil {
		return err
	}
	return SaveAccount(path, cfg)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
