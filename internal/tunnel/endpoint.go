package tunnel

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Endpoint is a Cloudflare WARP MASQUE server address.
type Endpoint struct {
	IP   net.IP
	Port int
}

// String renders the endpoint as "ip:port".
func (e Endpoint) String() string {
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(e.Port))
}

// IsIPv6 reports whether the endpoint uses an IPv6 address.
func (e Endpoint) IsIPv6() bool {
	return e.IP.To4() == nil
}

// UDPAddr returns the endpoint as a UDP address (used for QUIC/HTTP3).
func (e Endpoint) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: e.IP, Port: e.Port}
}

// TCPAddr returns the endpoint as a TCP address (used for the HTTP/2 fallback).
func (e Endpoint) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: e.IP, Port: e.Port}
}

// ParseEndpoint parses "1.2.3.4:443" or "[2606:4700::1]:443". A missing port
// falls back to defaultPort.
func ParseEndpoint(value string, defaultPort int) (Endpoint, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Endpoint{}, fmt.Errorf("端点为空")
	}

	host := value
	port := defaultPort
	if h, p, err := net.SplitHostPort(value); err == nil {
		host = h
		if p != "" {
			parsed, err := strconv.Atoi(p)
			if err != nil || parsed <= 0 || parsed > 65535 {
				return Endpoint{}, fmt.Errorf("端点 %q 的端口无效", value)
			}
			port = parsed
		}
	} else if strings.HasSuffix(value, ":") {
		return Endpoint{}, fmt.Errorf("端点 %q 缺少端口", value)
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	ip := net.ParseIP(host)
	if ip == nil {
		return Endpoint{}, fmt.Errorf("端点 %q 的地址不是合法 IP", value)
	}
	return Endpoint{IP: ip, Port: port}, nil
}

// ParseEndpoints parses a list of "ip:port" entries, skipping empty lines and
// deduplicating the result while preserving order.
func ParseEndpoints(values []string, defaultPort int) ([]Endpoint, error) {
	var (
		out  []Endpoint
		seen = make(map[string]struct{})
	)
	for _, raw := range values {
		for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			ep, err := ParseEndpoint(item, defaultPort)
			if err != nil {
				return nil, err
			}
			key := ep.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ep)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可用的端点")
	}
	return out, nil
}
