package derp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/cubis/zro/pkg/crypto"
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

// Server is a high-performance DERP relay server running on Edge PoPs.
type Server struct {
	keyPair  *crypto.KeyPair
	pubKey   [KeyLen]byte
	mu       sync.RWMutex
	clients  map[[KeyLen]byte]*clientSession
	listener net.Listener
}

type clientSession struct {
	pubKey [KeyLen]byte
	conn   net.Conn
	mu     sync.Mutex
}

// NewServer creates a new DERP relay server.
func NewServer(kp *crypto.KeyPair) (*Server, error) {
	pubBytes, err := parseKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	return &Server{
		keyPair: kp,
		pubKey:  pubBytes,
		clients: make(map[[KeyLen]byte]*clientSession),
	}, nil
}

// Serve accepts incoming DERP client connections.
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

// Close terminates the DERP server.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. Send FrameServerInfo containing server's public key
	serverInfo := make([]byte, 1+KeyLen)
	serverInfo[0] = FrameServerInfo
	copy(serverInfo[1:], s.pubKey[:])
	if err := writeFrame(conn, serverInfo); err != nil {
		return
	}

	// 2. Read FrameClientInfo with client's public key
	frame, err := readFrame(conn)
	if err != nil || len(frame) < 1+KeyLen || frame[0] != FrameClientInfo {
		return
	}

	var clientPubKey [KeyLen]byte
	copy(clientPubKey[:], frame[1:1+KeyLen])

	session := &clientSession{
		pubKey: clientPubKey,
		conn:   conn,
	}

	s.mu.Lock()
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

	// 3. Packet switching loop
	for {
		frame, err := readFrame(conn)
		if err != nil {
			return
		}
		if len(frame) == 0 {
			continue
		}

		switch frame[0] {
		case FrameSendPacket:
			// Frame: [Type 1B][DstPubKey 32B][Payload NB]
			if len(frame) < 1+KeyLen {
				continue
			}
			var dstKey [KeyLen]byte
			copy(dstKey[:], frame[1:1+KeyLen])
			payload := frame[1+KeyLen:]

			s.mu.RLock()
			targetSession, exists := s.clients[dstKey]
			s.mu.RUnlock()

			if exists {
				// Relay packet to destination client: [FrameRecvPacket][SrcKey][Payload]
				out := make([]byte, 1+KeyLen+len(payload))
				out[0] = FrameRecvPacket
				copy(out[1:1+KeyLen], clientPubKey[:])
				copy(out[1+KeyLen:], payload)

				targetSession.mu.Lock()
				_ = writeFrame(targetSession.conn, out)
				targetSession.mu.Unlock()
			}

		case FramePing:
			// Respond with Pong
			_ = writeFrame(conn, []byte{FramePong})

		case FrameKeepAlive:
			// No-op keepalive
		}
	}
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
}

// Packet represents an encapsulated packet received from a peer via DERP.
type Packet struct {
	SrcPubKey [KeyLen]byte
	Payload   []byte
}

// ConnectDERP connects to an Edge DERP relay server.
func ConnectDERP(ctx context.Context, serverAddr string, kp *crypto.KeyPair) (*Client, error) {
	pubBytes, err := parseKey(kp.PublicKey)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DERP server %s: %w", serverAddr, err)
	}

	// Read ServerInfo
	frame, err := readFrame(conn)
	if err != nil || len(frame) < 1+KeyLen || frame[0] != FrameServerInfo {
		conn.Close()
		return nil, fmt.Errorf("invalid DERP server handshake")
	}

	// Send ClientInfo
	clientInfo := make([]byte, 1+KeyLen)
	clientInfo[0] = FrameClientInfo
	copy(clientInfo[1:], pubBytes[:])
	if err := writeFrame(conn, clientInfo); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send DERP client handshake: %w", err)
	}

	c := &Client{
		serverAddr: serverAddr,
		keyPair:    kp,
		myPubKey:   pubBytes,
		conn:       conn,
		recvCh:     make(chan Packet, 64),
		closed:     make(chan struct{}),
	}

	go c.readLoop()
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
	return writeFrame(c.conn, frame)
}

// Recv returns a channel receiving packets relayed from peers.
func (c *Client) Recv() <-chan Packet {
	return c.recvCh
}

// Close disconnects from the DERP relay.
func (c *Client) Close() error {
	close(c.closed)
	return c.conn.Close()
}

func (c *Client) readLoop() {
	defer close(c.recvCh)
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
			case <-c.closed:
				return
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
