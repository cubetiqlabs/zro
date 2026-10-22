package derp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/dataplane/relay"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/time/rate"
)

// DERP Frame Types
const (
	FrameServerInfo byte = 0x01
	FrameClientInfo byte = 0x02
	FrameSendPacket byte = 0x03
	FrameRecvPacket byte = 0x04
	FrameKeepAlive  byte = 0x05
	FramePing       byte = 0x06
	FramePong       byte = 0x07

	KeyLen       = 32
	MaxPacketLen = 64 * 1024 // 64KB max WireGuard MTU / packet
)

var (
	ErrPacketTooLarge = errors.New("derp: packet exceeds maximum allowed size")
	ErrClientNotFound = errors.New("derp: destination client not connected to relay")
)

// Packet is a datagram relayed from a peer; see relay.Packet.
type Packet = relay.Packet

const (
	handshakeTimeout = 5 * time.Second
	idleTimeout      = 60 * time.Second // a healthy client keeps the session alive well within this
	keepAliveEvery   = 20 * time.Second
	nonceLen         = 16
)

// Server is a DERP relay running on Edge PoPs. Clients prove possession of
// their WireGuard private key during the handshake, and the relay forwards
// only between authenticated sessions.
type Server struct {
	keyPair  *crypto.KeyPair
	privKey  [KeyLen]byte
	pubKey   [KeyLen]byte
	mu       sync.RWMutex
	clients  map[[KeyLen]byte]*clientSession
	listener net.Listener
	local    *localEndpoint

	// Authorize, if set, decides which authenticated public keys may use the
	// relay. Without it any holder of a valid key pair is admitted.
	Authorize func(pub [KeyLen]byte) bool

	// Limits bounds connections and per-session throughput; zero fields are
	// unlimited. Set before Serve.
	Limits Limits

	conns   int            // open connections, including ones still handshaking
	ipConns map[string]int // open connections per source IP
	dropped atomic.Uint64
}

// Limits caps relay resource use. Over-rate packets are dropped, not queued or
// disconnected: WireGuard retransmits, and a flooding client only hurts itself.
type Limits struct {
	MaxConns      int // total open connections
	MaxConnsPerIP int // open connections per source IP (NATs share one)
	PacketsPerSec int // per session
	BytesPerSec   int // per session
}

// Dropped returns how many packets the rate limits have discarded.
func (s *Server) Dropped() uint64 { return s.dropped.Load() }

// admitConn reserves a connection slot for ip, or reports that a cap is hit.
func (s *Server) admitConn(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.Limits.MaxConns > 0 && s.conns >= s.Limits.MaxConns) ||
		(s.Limits.MaxConnsPerIP > 0 && s.ipConns[ip] >= s.Limits.MaxConnsPerIP) {
		return false
	}
	if s.ipConns == nil {
		s.ipConns = make(map[string]int)
	}
	s.conns++
	s.ipConns[ip]++
	return true
}

func (s *Server) releaseConn(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns--
	if s.ipConns[ip]--; s.ipConns[ip] <= 0 {
		delete(s.ipConns, ip)
	}
}

type clientSession struct {
	pubKey [KeyLen]byte
	conn   net.Conn
	mu     sync.Mutex
	pps    *rate.Limiter // nil = unlimited
	bps    *rate.Limiter
}

// allow reports whether a packet of n bytes is within the session's rate.
func (c *clientSession) allow(n int) bool {
	return (c.pps == nil || c.pps.Allow()) && (c.bps == nil || c.bps.AllowN(time.Now(), n))
}

// newLimiter allows perSec events per second with one second of burst, or at
// least min so a single maximum-size frame always fits.
func newLimiter(perSec, min int) *rate.Limiter {
	if perSec <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(perSec), max(perSec, min))
}

func (c *clientSession) write(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	return writeFrame(c.conn, frame)
}

// NewServer creates a new DERP relay server.
func NewServer(kp *crypto.KeyPair) (*Server, error) {
	pub, err := parseKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}
	priv, err := parseKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server private key: %w", err)
	}
	s := &Server{keyPair: kp, privKey: priv, pubKey: pub, clients: make(map[[KeyLen]byte]*clientSession)}
	s.local = newLocalEndpoint(s)
	return s, nil
}

// Local returns the relay endpoint of the server's own key: datagrams that
// clients address to the PoP arrive on its Recv, and Send reaches a client.
// The PoP's WireGuard device attaches to it so peers behind UDP-hostile
// networks can still handshake with the PoP.
func (s *Server) Local() relay.Transport { return s.local }

// Serve accepts incoming DERP client connections.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.admitConn(ip) {
			conn.Close()
			continue
		}
		go func() {
			defer s.releaseConn(ip)
			s.handleConn(conn)
		}()
	}
}

// Close terminates the DERP server.
func (s *Server) Close() error {
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		return l.Close()
	}
	return nil
}

// authMAC binds a handshake to the server nonce and the client key using the
// X25519 shared secret, which only the holder of the client's private key (or
// the server) can compute.
func authMAC(shared, nonce []byte, clientPub [KeyLen]byte) []byte {
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("zro-derp-v1"))
	mac.Write(nonce)
	mac.Write(clientPub[:])
	return mac.Sum(nil)
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// 1. ServerInfo: [type][server pub][nonce]
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	serverInfo := make([]byte, 0, 1+KeyLen+nonceLen)
	serverInfo = append(serverInfo, FrameServerInfo)
	serverInfo = append(serverInfo, s.pubKey[:]...)
	serverInfo = append(serverInfo, nonce...)
	if err := writeFrame(conn, serverInfo); err != nil {
		return
	}

	// 2. ClientInfo: [type][client pub][mac] with proof of key possession.
	frame, err := readFrame(conn)
	if err != nil || len(frame) != 1+KeyLen+sha256.Size || frame[0] != FrameClientInfo {
		return
	}
	var clientPubKey [KeyLen]byte
	copy(clientPubKey[:], frame[1:1+KeyLen])
	shared, err := curve25519.X25519(s.privKey[:], clientPubKey[:])
	if err != nil || !hmac.Equal(frame[1+KeyLen:], authMAC(shared, nonce, clientPubKey)) {
		return
	}
	if s.Authorize != nil && !s.Authorize(clientPubKey) {
		return
	}
	if clientPubKey == s.pubKey {
		return
	}

	session := &clientSession{
		pubKey: clientPubKey, conn: conn,
		pps: newLimiter(s.Limits.PacketsPerSec, 1),
		bps: newLimiter(s.Limits.BytesPerSec, MaxPacketLen+64),
	}
	s.mu.Lock()
	if old := s.clients[clientPubKey]; old != nil {
		_ = old.conn.Close() // a reconnect replaces the stale session
	}
	s.clients[clientPubKey] = session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.clients[clientPubKey] == session {
			delete(s.clients, clientPubKey)
		}
		s.mu.Unlock()
	}()

	slog.Debug("DERP client connected to relay", "pubkey", fmt.Sprintf("%x", clientPubKey[:8]))

	// 3. Packet switching loop. The source key of relayed packets is always the
	// authenticated session key, never anything the client wrote.
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		frame, err := readFrame(conn)
		if err != nil {
			return
		}
		if len(frame) == 0 {
			continue
		}

		switch frame[0] {
		case FrameSendPacket:
			if len(frame) < 1+KeyLen {
				continue
			}
			var dstKey [KeyLen]byte
			copy(dstKey[:], frame[1:1+KeyLen])
			payload := frame[1+KeyLen:]
			if !session.allow(len(frame)) {
				s.dropped.Add(1)
				continue
			}

			if dstKey == s.pubKey {
				s.local.deliver(clientPubKey, payload)
				continue
			}
			s.mu.RLock()
			target := s.clients[dstKey]
			s.mu.RUnlock()
			if target != nil {
				_ = target.write(recvFrame(clientPubKey, payload))
			}

		case FramePing:
			_ = session.write([]byte{FramePong})

		case FrameKeepAlive:
			// Receiving it refreshed the idle deadline.
		}
	}
}

func recvFrame(src [KeyLen]byte, payload []byte) []byte {
	out := make([]byte, 1+KeyLen+len(payload))
	out[0] = FrameRecvPacket
	copy(out[1:1+KeyLen], src[:])
	copy(out[1+KeyLen:], payload)
	return out
}

// localEndpoint is the server's own address on the relay.
type localEndpoint struct {
	srv    *Server
	recvCh chan Packet
}

func newLocalEndpoint(s *Server) *localEndpoint {
	return &localEndpoint{srv: s, recvCh: make(chan Packet, 256)}
}

func (l *localEndpoint) deliver(src [KeyLen]byte, payload []byte) {
	pkt := Packet{SrcPubKey: src, Payload: append([]byte(nil), payload...)}
	select {
	case l.recvCh <- pkt:
	default: // WireGuard retransmits; never block a client's session on the PoP
	}
}

func (l *localEndpoint) Recv() <-chan Packet { return l.recvCh }

func (l *localEndpoint) Send(dst [KeyLen]byte, packet []byte) error {
	if len(packet) > MaxPacketLen {
		return ErrPacketTooLarge
	}
	l.srv.mu.RLock()
	target := l.srv.clients[dst]
	l.srv.mu.RUnlock()
	if target == nil {
		return ErrClientNotFound
	}
	return target.write(recvFrame(l.srv.pubKey, packet))
}

// Client is a DERP relay client running inside zro-node.
type Client struct {
	serverAddr string
	keyPair    *crypto.KeyPair
	myPubKey   [KeyLen]byte
	conn       net.Conn
	mu         sync.Mutex
	recvCh     chan Packet
	closed     chan struct{}
	closeOnce  sync.Once
}

// ConnectDERP connects to an Edge DERP relay server and proves possession of
// kp's private key.
func ConnectDERP(ctx context.Context, serverAddr string, kp *crypto.KeyPair) (*Client, error) {
	pubBytes, err := parseKey(kp.PublicKey)
	if err != nil {
		return nil, err
	}
	privBytes, err := parseKey(kp.PrivateKey)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DERP server %s: %w", serverAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	frame, err := readFrame(conn)
	if err != nil || len(frame) != 1+KeyLen+nonceLen || frame[0] != FrameServerInfo {
		conn.Close()
		return nil, fmt.Errorf("invalid DERP server handshake")
	}
	serverPub, nonce := frame[1:1+KeyLen], frame[1+KeyLen:]

	shared, err := curve25519.X25519(privBytes[:], serverPub)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("DERP key agreement failed: %w", err)
	}
	clientInfo := make([]byte, 0, 1+KeyLen+sha256.Size)
	clientInfo = append(clientInfo, FrameClientInfo)
	clientInfo = append(clientInfo, pubBytes[:]...)
	clientInfo = append(clientInfo, authMAC(shared, nonce, pubBytes)...)
	if err := writeFrame(conn, clientInfo); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send DERP client handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	c := &Client{
		serverAddr: serverAddr,
		keyPair:    kp,
		myPubKey:   pubBytes,
		conn:       conn,
		recvCh:     make(chan Packet, 256),
		closed:     make(chan struct{}),
	}
	go c.readLoop()
	go c.keepAlive()
	return c, nil
}

// Send forwards an encapsulated packet to dstPubKey via the DERP relay.
func (c *Client) Send(dstPubKey [KeyLen]byte, packet []byte) error {
	if len(packet) > MaxPacketLen {
		return ErrPacketTooLarge
	}

	frame := make([]byte, 1+KeyLen+len(packet))
	frame[0] = FrameSendPacket
	copy(frame[1:1+KeyLen], dstPubKey[:])
	copy(frame[1+KeyLen:], packet)

	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	return writeFrame(c.conn, frame)
}

// Recv returns a channel receiving packets relayed from peers. It is closed
// when the connection ends.
func (c *Client) Recv() <-chan Packet { return c.recvCh }

// Done is closed when the connection to the relay has ended.
func (c *Client) Done() <-chan struct{} { return c.closed }

// Close disconnects from the DERP relay.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.conn.Close()
}

func (c *Client) keepAlive() {
	ticker := time.NewTicker(keepAliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			c.mu.Lock()
			_ = c.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			err := writeFrame(c.conn, []byte{FrameKeepAlive})
			c.mu.Unlock()
			if err != nil {
				_ = c.Close()
				return
			}
		}
	}
}

func (c *Client) readLoop() {
	defer close(c.recvCh)
	defer c.closeOnce.Do(func() { close(c.closed) })
	for {
		frame, err := readFrame(c.conn)
		if err != nil {
			return
		}
		if len(frame) == 0 {
			continue
		}

		if frame[0] == FrameRecvPacket && len(frame) >= 1+KeyLen {
			var srcKey [KeyLen]byte
			copy(srcKey[:], frame[1:1+KeyLen])
			payload := make([]byte, len(frame)-(1+KeyLen))
			copy(payload, frame[1+KeyLen:])

			select {
			case c.recvCh <- Packet{SrcPubKey: srcKey, Payload: payload}:
			default: // WireGuard retransmits; do not stall the connection
			}
		}
	}
}

func writeFrame(w io.Writer, payload []byte) error {
	length := uint32(len(payload))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxPacketLen+KeyLen+10 {
		return nil, ErrPacketTooLarge
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parseKey(b64 string) ([KeyLen]byte, error) {
	var key [KeyLen]byte
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return key, fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(decoded) != KeyLen {
		return key, fmt.Errorf("invalid key length: expected 32, got %d", len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}
