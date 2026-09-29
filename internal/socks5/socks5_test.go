package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// echoDialer returns a dialer that connects to a local echo server, so the
// whole path (handshake + relay) can be exercised without a network.
func echoDialer(t *testing.T) (DialFunc, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	return dial, func() {
		close(done)
		_ = ln.Close()
	}
}

func startServer(t *testing.T, auth Credentials, dial DialFunc) *Server {
	t.Helper()
	s := &Server{
		Addr:             "127.0.0.1:0",
		Auth:             auth,
		Dial:             dial,
		HandshakeTimeout: 3 * time.Second,
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// clientHandshake performs the greeting, optional auth and the CONNECT
// request. It returns the reader so the caller can consume the relay.
func clientHandshake(t *testing.T, conn net.Conn, user, pass, host string, port uint16) *bufio.Reader {
	t.Helper()
	br := bufio.NewReader(conn)

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(br, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	wantMethod := byte(0x00)
	if user != "" {
		wantMethod = 0x02
	}
	if reply[1] != wantMethod {
		t.Fatalf("selected method = 0x%02x, want 0x%02x", reply[1], wantMethod)
	}

	if user != "" {
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(br, authReply); err != nil {
			t.Fatalf("read auth reply: %v", err)
		}
		if authReply[1] != 0x00 {
			return nil // authentication rejected
		}
	}

	req := []byte{0x05, cmdConnect, 0x00, atypDomain, byte(len(host))}
	req = append(req, host...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp := make([]byte, 10) // domain reply is longer; read header first
	if _, err := io.ReadFull(br, resp[:4]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("reply version = %d", resp[0])
	}
	// Drain the remaining bind address.
	var skip int
	switch resp[3] {
	case atypIPv4:
		skip = 4 + 2
	case atypIPv6:
		skip = 16 + 2
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(br, lenByte); err != nil {
			t.Fatalf("read bind domain length: %v", err)
		}
		skip = int(lenByte[0]) + 2
	}
	if _, err := io.ReadFull(br, make([]byte, skip)); err != nil {
		t.Fatalf("read bind address: %v", err)
	}
	if resp[1] != repSuccess {
		t.Fatalf("reply code = 0x%02x, want success", resp[1])
	}
	return br
}

func TestSOCKS5ConnectWithoutAuth(t *testing.T) {
	dial, stop := echoDialer(t)
	defer stop()

	s := startServer(t, Credentials{}, dial)
	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	br := clientHandshake(t, conn, "", "", "example.com", 443)
	_ = br

	payload := []byte("hello warp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestSOCKS5ConnectWithAuth(t *testing.T) {
	dial, stop := echoDialer(t)
	defer stop()

	s := startServer(t, Credentials{Username: "alice", Password: "s3cret"}, dial)
	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if br := clientHandshake(t, conn, "alice", "s3cret", "example.com", 443); br == nil {
		t.Fatal("valid credentials were rejected")
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestSOCKS5RejectsWrongPassword(t *testing.T) {
	dial, stop := echoDialer(t)
	defer stop()

	s := startServer(t, Credentials{Username: "alice", Password: "s3cret"}, dial)
	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if br := clientHandshake(t, conn, "alice", "wrong", "example.com", 443); br != nil {
		t.Fatal("wrong password must not establish a session")
	}
}

func TestSOCKS5RejectsMissingAuthMethod(t *testing.T) {
	dial, stop := echoDialer(t)
	defer stop()

	s := startServer(t, Credentials{Username: "alice", Password: "s3cret"}, dial)
	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Offer only "no authentication".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != authNoAccept {
		t.Fatalf("method = 0x%02x, want 0x%02x", reply[1], authNoAccept)
	}
}

func TestSOCKS5ReportsDialFailure(t *testing.T) {
	s := startServer(t, Credentials{}, func(context.Context, string, string) (net.Conn, error) {
		return nil, io.ErrUnexpectedEOF
	})

	conn, err := net.Dial("tcp", s.BoundAddr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Handshake succeeds, CONNECT must fail.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := io.ReadFull(br, make([]byte, 2)); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	req := []byte{0x05, cmdConnect, 0x00, atypIPv4, 1, 2, 3, 4, 0x01, 0xbb}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := make([]byte, 10)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, resp); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if resp[1] == repSuccess {
		t.Fatal("dial failure must not report success")
	}
}

func TestCredentialsRequired(t *testing.T) {
	if (Credentials{}).Required() {
		t.Fatal("empty credentials must not require auth")
	}
	if (Credentials{Username: "a"}).Required() {
		t.Fatal("username without password must not require auth")
	}
	if !(Credentials{Username: "a", Password: "b"}).Required() {
		t.Fatal("complete credentials must require auth")
	}
}
