package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5Server implements an RFC 1928 SOCKS5 proxy server allowing any application
// to route arbitrary TCP/HTTP/HTTPS/SSH traffic through the ZRO overlay network.
type SOCKS5Server struct {
	mu       sync.Mutex
	listener net.Listener
	closed   bool
	dialer   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSOCKS5Server creates a SOCKS5 server that opens every connection with
// dialer. The dialer decides what is reachable; there is deliberately no
// default, because a default of "the host network" would make this an open proxy.
func NewSOCKS5Server(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) *SOCKS5Server {
	if dialer == nil {
		panic("tunnel: NewSOCKS5Server requires a dialer")
	}
	return &SOCKS5Server{dialer: dialer}
}

const (
	socksHandshakeTimeout = 10 * time.Second
	socksDialTimeout      = 10 * time.Second
)

// Serve accepts incoming connections on listener l.
func (s *SOCKS5Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed { // Close won the race with Serve
		s.mu.Unlock()
		return l.Close()
	}
	s.listener = l
	s.mu.Unlock()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

// ListenAndServe starts listening on listenAddr.
func (s *SOCKS5Server) ListenAndServe(listenAddr string) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind SOCKS5 listener: %w", err)
	}
	slog.Info("ZRO SOCKS5 proxy listening", "addr", listenAddr)
	return s.Serve(l)
}

// Close stops the SOCKS5 server.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	s.closed = true
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		return l.Close()
	}
	return nil
}

func (s *SOCKS5Server) handleClient(conn net.Conn) {
	defer conn.Close()
	// A client that stalls mid-handshake must not hold the connection forever.
	_ = conn.SetDeadline(time.Now().Add(socksHandshakeTimeout))

	// 1. Version & Method negotiation
	// [VER: 1B (0x05)][NMETHODS: 1B][METHODS: NB]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return // only SOCKS5 supported
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Reply with NO AUTH REQUIRED (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request Details
	// [VER: 0x05][CMD: 1B][RSV: 0x00][ATYP: 1B][DST.ADDR][DST.PORT: 2B]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	if cmd != 0x01 { // 0x01 = CONNECT
		_ = s.sendReply(conn, 0x07) // command not supported
		return
	}

	atyp := reqHeader[3]
	var targetHost string

	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	case 0x03: // Domain name ([Len 1B][Domain String])
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetHost = string(domain)

	case 0x04: // IPv6 (16 bytes)
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	default:
		_ = s.sendReply(conn, 0x08) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))

	// 3. Dial target destination via overlay dialer
	dialCtx, cancel := context.WithTimeout(context.Background(), socksDialTimeout)
	destConn, err := s.dialer(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		_ = s.sendReply(conn, 0x04) // host unreachable
		return
	}
	defer destConn.Close()

	// 4. Send SUCCESS reply (0x00)
	if err := s.sendReply(conn, 0x00); err != nil {
		return
	}

	// 5. Bidirectional copy (no deadline once the tunnel is established)
	_ = conn.SetDeadline(time.Time{})
	_ = bridge(conn, destConn, context.Background())
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte) error {
	// [VER: 0x05][REP: 1B][RSV: 0x00][ATYP: 0x01 (IPv4)][BND.ADDR: 0.0.0.0][BND.PORT: 0]
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}
