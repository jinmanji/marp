package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startProxy(t *testing.T, auth Credentials, target string) *Server {
	t.Helper()
	s := &Server{
		Addr:           "127.0.0.1:0",
		Auth:           auth,
		ConnectTimeout: 3 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func proxyURL(t *testing.T, s *Server, auth Credentials) *url.URL {
	t.Helper()
	u := &url.URL{Scheme: "http", Host: s.BoundAddr().String()}
	if auth.Required() {
		u.User = url.UserPassword(auth.Username, auth.Password)
	}
	return u
}

func TestForwardRequiresAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "backend-ok")
	}))
	defer backend.Close()

	auth := Credentials{Username: "bob", Password: "hunter2"}
	s := startProxy(t, auth, backend.Listener.Addr().String())

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL(t, s, Credentials{}))},
	}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request without credentials: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic", got)
	}
}

func TestForwardWithAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "yes" {
			t.Errorf("custom header lost: %q", r.Header.Get("X-Test"))
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization must not be forwarded upstream")
		}
		_, _ = io.WriteString(w, "backend-ok")
	}))
	defer backend.Close()

	auth := Credentials{Username: "bob", Password: "hunter2"}
	s := startProxy(t, auth, backend.Listener.Addr().String())

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL(t, s, auth))},
	}
	req, err := http.NewRequest(http.MethodGet, backend.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Test", "yes")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "backend-ok" {
		t.Fatalf("body = %q, want %q", body, "backend-ok")
	}
}

func TestConnectTunnel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tunnel-ok")
	}))
	defer backend.Close()

	auth := Credentials{Username: "bob", Password: "hunter2"}
	s := startProxy(t, auth, backend.Listener.Addr().String())

	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Unauthorized CONNECT must be refused before any hijack happens.
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Listener.Addr(), backend.Listener.Addr())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read unauthorized response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}

	// Authorized CONNECT.
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		backend.Listener.Addr(), backend.Listener.Addr(), proxyBasicHeader(auth.Username, auth.Password))

	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read authorized response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// The connection is now a raw tunnel to the backend.
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backend.URL, backend.Listener.Addr())
	tunneled, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read tunnelled response: %v", err)
	}
	defer tunneled.Body.Close()
	body, _ := io.ReadAll(tunneled.Body)
	if !strings.Contains(string(body), "tunnel-ok") {
		t.Fatalf("tunnelled body = %q", body)
	}
}

func TestAuthorityWithPort(t *testing.T) {
	tests := []struct {
		in   string
		def  string
		want string
	}{
		{"example.com:8443", "443", "example.com:8443"},
		{"example.com", "443", "example.com:443"},
		{"1.2.3.4:80", "443", "1.2.3.4:80"},
		{"[2606:4700::1]:9000", "443", "[2606:4700::1]:9000"},
		{"[2606:4700::1]", "443", "[2606:4700::1]:443"},
		{"", "443", ""},
	}
	for _, tc := range tests {
		if got := authorityWithPort(tc.in, tc.def); got != tc.want {
			t.Fatalf("authorityWithPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCredentialsMatches(t *testing.T) {
	auth := Credentials{Username: "bob", Password: "hunter2"}
	good := proxyBasicHeader("bob", "hunter2")

	if !auth.matches(good) {
		t.Fatalf("correct credentials were rejected (%q)", good)
	}
	if auth.matches("") {
		t.Fatal("empty header must be rejected")
	}
	if auth.matches("Basic " + strings.Repeat("A", len(good))) {
		t.Fatal("wrong credentials were accepted")
	}
	if auth.matches(proxyBasicHeader("bob", "wrong")) {
		t.Fatal("wrong password was accepted")
	}
	if auth.matches(proxyBasicHeader("eve", "hunter2")) {
		t.Fatal("wrong username was accepted")
	}

	open := Credentials{}
	if !open.matches("") || !open.matches("anything") {
		t.Fatal("auth disabled must accept everything")
	}
}

// proxyBasicHeader builds the value clients send in Proxy-Authorization.
func proxyBasicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
