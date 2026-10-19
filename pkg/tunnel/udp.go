package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// UDPTunnel bridges UDP datagrams between a local listener and a remote overlay endpoint.
type UDPTunnel struct {
	mu         sync.Mutex
	localConn  *net.UDPConn
	remoteAddr *net.UDPAddr
	sessions   map[string]*udpSession
	closed     bool
}

type udpSession struct {
	upstreamConn *net.UDPConn
	lastActive   time.Time
}

// NewUDPTunnel creates and starts a bidirectional UDP datagram tunnel.
func NewUDPTunnel(listenAddr, targetAddr string) (*UDPTunnel, error) {
	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local UDP address: %w", err)
	}

	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind local UDP listener: %w", err)
	}

	tunnel := &UDPTunnel{
		localConn:  conn,
		remoteAddr: rAddr,
		sessions:   make(map[string]*udpSession),
	}

	slog.Info("ZRO UDP tunnel listening", "listen", listenAddr, "target", targetAddr)
	go tunnel.readLoop()
	return tunnel, nil
}

// Close terminates the UDP tunnel.
func (u *UDPTunnel) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	for _, sess := range u.sessions {
		_ = sess.upstreamConn.Close()
	}
	return u.localConn.Close()
}

func (u *UDPTunnel) readLoop() {
	buf := make([]byte, 65535)

	for {
		n, clientAddr, err := u.localConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		sessionKey := clientAddr.String()
		u.mu.Lock()
		sess, exists := u.sessions[sessionKey]
		if !exists {
			// Create upstream UDP socket to remote destination
			upConn, err := net.DialUDP("udp", nil, u.remoteAddr)
			if err != nil {
				u.mu.Unlock()
				continue
			}

			sess = &udpSession{
				upstreamConn: upConn,
				lastActive:   time.Now(),
			}
			u.sessions[sessionKey] = sess

			// Upstream reader
			go u.upstreamReader(sess, clientAddr)
		}
		sess.lastActive = time.Now()
		u.mu.Unlock()

		_, _ = sess.upstreamConn.Write(buf[:n])
	}
}

func (u *UDPTunnel) upstreamReader(sess *udpSession, clientAddr *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		_ = sess.upstreamConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := sess.upstreamConn.Read(buf)
		if err != nil {
			return
		}

		_, _ = u.localConn.WriteToUDP(buf[:n], clientAddr)
	}
}

// PipeTCPListener accepts connections on a local TCP address and tunnels them to a remote destination.
func PipeTCPListener(ctx context.Context, listenAddr, targetAddr string) (net.Listener, error) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind TCP tunnel listener %s: %w", listenAddr, err)
	}

	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				var d net.Dialer
				upstream, err := d.DialContext(ctx, "tcp", targetAddr)
				if err != nil {
					return
				}
				defer upstream.Close()

				errCh := make(chan error, 2)
				go func() { _, err := ioCopy(upstream, c); errCh <- err }()
				go func() { _, err := ioCopy(c, upstream); errCh <- err }()
				select {
				case <-ctx.Done():
				case <-errCh:
				}
			}(conn)
		}
	}()

	return l, nil
}

func ioCopy(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
		}
		if err != nil {
			return written, err
		}
	}
}
