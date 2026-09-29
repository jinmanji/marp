// Package socks5 implements a minimal SOCKS5 (RFC 1928) server with
// username/password authentication (RFC 1929) on top of a pluggable dialer.
//
// Only the CONNECT command is supported, which is exactly what an HTTP/SOCKS
// proxy sitting on top of a TCP-only MASQUE tunnel can offer.
package socks5

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// Protocol constants.
const (
	version5 = 0x05

	authNone      = 0x00
	authUserPass  = 0x02
	authNoAccept  = 0xFF
	authVersion   = 0x01
	authSuccess   = 0x00
	authFailure   = 0x01
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repFailure    = 0x01
	repNotAllowed = 0x02
	repNetUnreach = 0x03
	repHostUnrch  = 0x04
	repCmdNoSupp  = 0x07
	repAtypNoSupp = 0x08

	userAuthMaxLen = 255
)

// Credentials for username/password authentication.
type Credentials struct {
	Username string
	Password string
}

// Required reports whether authentication must be performed.
func (c Credentials) Required() bool { return c.Username != "" && c.Password != "" }

// DialFunc establishes an outbound connection. It is an alias so that the
// SOCKS5 and HTTP servers accept the same dialer implementation.
type DialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// Server is a SOCKS5 listener.
type Server struct {
	// Addr is the listen address, e.g. "127.0.0.1:1080".
	Addr string
	// Auth, when both fields are set, enables username/password auth.
	Auth Credentials
	// Dial opens the tunnel to the requested destination.
	Dial DialFunc
	// Logger receives diagnostics; nil disables logging.
	Logger *log.Logger

	// HandshakeTimeout bounds the client handshake. Zero means 10s.
	HandshakeTimeout time.Duration
	// ConnectTimeout bounds dialing the destination. Zero means no extra
	// limit beyond whatever the dialer applies.
	ConnectTimeout time.Duration
	// IdleTimeout closes idle connections. Zero means 5 minutes.
	IdleTimeout time.Duration

	listener net.Listener
	closed   chan struct{}
}

// Listen binds the configured address without serving yet, so that the caller
// can report the effective port before traffic starts.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("监听 SOCKS5 地址 %s 失败: %w", s.Addr, err)
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

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// Close stops the listener.
func (s *Server) Close() error {
	if s.closed != nil {
		select {
		case <-s.closed:
		default:
			close(s.closed)
		}
	}
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.HandshakeTimeout > 0 {
		return s.HandshakeTimeout
	}
	return 10 * time.Second
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout()))

	reader := bufio.NewReader(conn)

	if err := s.negotiate(conn, reader); err != nil {
		s.logf("socks5 %s: 握手失败: %v", remote, err)
		return
	}

	target, reply, err := readRequest(reader)
	if err != nil {
		_ = writeReply(conn, reply, net.IPv4zero, 0)
		s.logf("socks5 %s: 请求无效: %v", remote, err)
		return
	}

	_ = conn.SetDeadline(time.Time{})

	ctx := context.Background()
	if s.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.ConnectTimeout)
		defer cancel()
	}

	if s.Dial == nil {
		_ = writeReply(conn, repNetUnreach, net.IPv4zero, 0)
		return
	}

	upstream, err := s.Dial(ctx, "tcp", target)
	if err != nil {
		_ = writeReply(conn, repHostUnrch, net.IPv4zero, 0)
		s.logf("socks5 %s: 连接 %s 失败: %v", remote, target, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	if err := writeReply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}

	if s.IdleTimeout > 0 {
		idle := s.IdleTimeout
		_ = conn.SetDeadline(time.Now().Add(idle))
		_ = upstream.SetDeadline(time.Now().Add(idle))
	}

	s.logf("socks5 %s -> %s", remote, target)
	relay(conn, reader, upstream)
	if s.IdleTimeout > 0 {
		// Clear deadlines before the next use of the connection.
		_ = conn.SetDeadline(time.Time{})
		_ = upstream.SetDeadline(time.Time{})
	}
}

// negotiate performs method selection and, when configured, the
// username/password sub-negotiation.
func (s *Server) negotiate(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != version5 {
		return fmt.Errorf("不支持的 SOCKS 版本 %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	want := byte(authNone)
	if s.Auth.Required() {
		want = authUserPass
	}

	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = conn.Write([]byte{version5, authNoAccept})
		return errors.New("客户端未提供可用的认证方式")
	}
	if _, err := conn.Write([]byte{version5, want}); err != nil {
		return err
	}
	if want == authNone {
		return nil
	}
	return s.authenticate(conn, reader)
}

func (s *Server) authenticate(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return fmt.Errorf("不支持的认证子协议版本 %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return err
	}
	plen, err := reader.ReadByte()
	if err != nil {
		return err
	}
	password := make([]byte, int(plen))
	if _, err := io.ReadFull(reader, password); err != nil {
		return err
	}

	okUser := subtle.ConstantTimeCompare(username, []byte(s.Auth.Username)) == 1
	okPass := subtle.ConstantTimeCompare(password, []byte(s.Auth.Password)) == 1
	if !okUser || !okPass {
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return errors.New("用户名或密码错误")
	}
	if _, err := conn.Write([]byte{authVersion, authSuccess}); err != nil {
		return err
	}
	return nil
}

// readRequest parses a SOCKS5 request and returns the target as "host:port".
func readRequest(reader *bufio.Reader) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", repFailure, err
	}
	if header[0] != version5 {
		return "", repFailure, fmt.Errorf("不支持的 SOCKS 版本 %d", header[0])
	}

	cmd := header[1]
	atyp := header[3]

	if cmd != cmdConnect {
		return "", repCmdNoSupp, fmt.Errorf("不支持的命令 0x%02x", cmd)
	}

	var host string
	switch atyp {
	case atypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", repFailure, err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", repFailure, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		l, err := reader.ReadByte()
		if err != nil {
			return "", repFailure, err
		}
		if l == 0 {
			return "", repFailure, errors.New("域名为空")
		}
		buf := make([]byte, int(l))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", repFailure, err
		}
		host = string(buf)
	default:
		return "", repAtypNoSupp, fmt.Errorf("不支持的地址类型 0x%02x", atyp)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", repFailure, err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	if port == 0 {
		return "", repFailure, errors.New("端口为 0")
	}

	return net.JoinHostPort(host, strconv.Itoa(port)), repSuccess, nil
}

func writeReply(conn net.Conn, code byte, ip net.IP, port int) error {
	reply := []byte{version5, code, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, atypIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, atypIPv6)
		reply = append(reply, ip.To16()...)
	}
	reply = append(reply, byte(port>>8), byte(port))
	_, err := conn.Write(reply)
	return err
}

// relay copies data in both directions until either side finishes. The
// buffered reader is used for the client direction so no bytes that were read
// ahead during the handshake are lost.
func relay(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	errs := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstream, clientReader)
		closeWrite(upstream)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		closeWrite(client)
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil && !errors.Is(err, io.EOF) {
			_ = err
		}
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
