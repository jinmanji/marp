// Package httpproxy implements an authenticating forward HTTP proxy.
//
// It supports both the CONNECT method (used for HTTPS and any other TCP
// traffic) and plain forwarded requests, both tunnelled through the pluggable
// dialer.
package httpproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Credentials for HTTP Basic proxy authentication.
type Credentials struct {
	Username string
	Password string
}

// Required reports whether authentication must be enforced.
func (c Credentials) Required() bool { return c.Username != "" && c.Password != "" }

// expectedHeader returns the value of a well formed Proxy-Authorization
// header, or "" when authentication is disabled.
//
// Note: http.Request.SetBasicAuth writes the "Authorization" header, not
// "Proxy-Authorization", so the proxy header has to be built by hand.
func (c Credentials) expectedHeader() string {
	if !c.Required() {
		return ""
	}
	token := base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))
	return "Basic " + token
}

// matches performs a constant-time comparison of the presented credentials.
func (c Credentials) matches(header string) bool {
	expected := c.expectedHeader()
	if expected == "" {
		return true
	}
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(expected)) == 1
}

// DialFunc establishes an outbound connection through the tunnel. It is an
// alias so that the SOCKS5 and HTTP servers accept the same dialer.
type DialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// Relayer copies traffic in both directions until either side closes.
type Relayer func(a, b net.Conn)

// Server is an HTTP proxy listener.
type Server struct {
	// Addr is the listen address, e.g. "127.0.0.1:8000".
	Addr string
	// Auth, when both fields are set, enables Basic proxy authentication.
	Auth Credentials
	// Dial opens the tunnel to the requested destination.
	Dial DialFunc
	// Relay copies bytes between the client and the tunnel. When nil an
	// internal bidirectional copy is used.
	Relay Relayer
	// Logger receives diagnostics; nil disables logging.
	Logger *log.Logger
	// ConnectTimeout bounds dialing the destination.
	ConnectTimeout time.Duration

	listener net.Listener
	server   *http.Server
	closed   chan struct{}
}

// Listen binds the configured address without serving yet.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("监听 HTTP 代理地址 %s 失败: %w", s.Addr, err)
	}
	s.listener = ln
	s.closed = make(chan struct{})
	return nil
}

// BoundAddr returns the bound address, or nil when Listen has not been called.
func (s *Server) BoundAddr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve runs the proxy until Close is called.
func (s *Server) Serve() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	handler := http.HandlerFunc(s.handle)
	s.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}
	err := s.server.Serve(s.listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Close stops the listener and waits for in-flight requests to finish.
func (s *Server) Close(ctx context.Context) error {
	if s.closed != nil {
		select {
		case <-s.closed:
		default:
			close(s.closed)
		}
	}
	if s.server == nil {
		if s.listener != nil {
			return s.listener.Close()
		}
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.matches(r.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="marp"`)
		http.Error(w, "需要代理认证", http.StatusProxyAuthRequired)
		s.logf("http 代理: %s %s 认证失败", r.RemoteAddr, r.URL)
		return
	}
	if s.Dial == nil {
		http.Error(w, "代理未配置", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleForward(w, r)
}

func (s *Server) dialCtx(ctx context.Context, network, address string) (net.Conn, error) {
	if s.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.ConnectTimeout)
		defer cancel()
	}
	return s.Dial(ctx, network, address)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := authorityWithPort(r.Host, "443")

	upstream, err := s.dialCtx(r.Context(), "tcp", target)
	if err != nil {
		s.logf("http 代理: 连接 %s 失败: %v", target, err)
		http.Error(w, "无法连接到目标", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = upstream.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持连接劫持", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		s.logf("http 代理: 劫持连接失败: %v", err)
		return
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	s.logf("http 代理: CONNECT %s", target)
	s.relay(client, upstream)
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	target := authorityWithPort(r.Host, "80")

	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 32,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialCtx(ctx, network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	if outbound.URL.Scheme == "" {
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = r.Host
	}
	outbound.Header = r.Header.Clone()
	outbound.Header.Del("Proxy-Authorization")
	outbound.Header.Del("Proxy-Connection")
	outbound.Close = false

	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		s.logf("http 代理: 请求 %s 失败: %v", outbound.URL, err)
		http.Error(w, "无法访问目标", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logf("http 代理: 转发响应体失败: %v", err)
	}
	_ = target
}

func (s *Server) relay(a, b net.Conn) {
	if s.Relay != nil {
		s.Relay(a, b)
		return
	}
	errs := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		closeWrite(b)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(a, b)
		closeWrite(a)
		errs <- err
	}()
	for i := 0; i < 2; i++ {
		<-errs
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// authorityWithPort normalises the request authority into a "host:port"
// string usable as a tunnel target.
func authorityWithPort(authority, defaultPort string) string {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return authority
	}
	if host, port, err := net.SplitHostPort(authority); err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port)
	}
	host := strings.TrimPrefix(authority, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" {
		return authority
	}
	return net.JoinHostPort(host, defaultPort)
}
