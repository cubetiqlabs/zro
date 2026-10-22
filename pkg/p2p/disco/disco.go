package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/crypto"
)

// Disco message types
const (
	TypePing      byte = 0x01
	TypePong      byte = 0x02
	TypeCallMe    byte = 0x03
	TypeHeartbeat byte = 0x04

	MagicDisco = 0x5a524f44 // "ZROD" in hex
	TxIDLen    = 12
	KeyLen     = 32
)

var (
	ErrInvalidMagic = errors.New("disco: invalid magic header")
	ErrPacketShort  = errors.New("disco: packet too short")
)

// Message represents a parsed discovery protocol message.
type Message struct {
	Type        byte
	TxID        [TxIDLen]byte
	SenderKey   string
	Timestamp   time.Time
	ReflexiveIP net.IP
	ReflexPort  int
	Endpoints   []string // for CallMe
}

// Engine coordinates peer discovery and endpoint probing over UDP.
type Engine struct {
	mu           sync.Mutex
	keyPair      *crypto.KeyPair
	pendingPings map[[TxIDLen]byte]*pendingPing
	udpConn      *net.UDPConn
}

type pendingPing struct {
	sentAt time.Time
	dest   string
	respCh chan pongResult
}

type pongResult struct {
	rtt           time.Duration
	reflexiveAddr *net.UDPAddr
}

// NewEngine creates a new peer discovery engine.
func NewEngine(kp *crypto.KeyPair, conn *net.UDPConn) *Engine {
	return &Engine{
		keyPair:      kp,
		pendingPings: make(map[[TxIDLen]byte]*pendingPing),
		udpConn:      conn,
	}
}

// SendPing transmits a discovery Ping to a candidate remote endpoint and waits for Pong.
func (e *Engine) SendPing(destAddr string, timeout time.Duration) (time.Duration, *net.UDPAddr, error) {
	dst, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve target address: %w", err)
	}

	var txID [TxIDLen]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return 0, nil, err
	}

	resCh := make(chan pongResult, 1)
	e.mu.Lock()
	e.pendingPings[txID] = &pendingPing{
		sentAt: time.Now(),
		dest:   destAddr,
		respCh: resCh,
	}
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.pendingPings, txID)
		e.mu.Unlock()
	}()

	// Build Ping packet:
	// [4B Magic][1B Type][12B TxID][8B Timestamp][32B SenderKey]
	packet := make([]byte, 4+1+TxIDLen+8+KeyLen)
	binary.BigEndian.PutUint32(packet[0:4], MagicDisco)
	packet[4] = TypePing
	copy(packet[5:5+TxIDLen], txID[:])
	binary.BigEndian.PutUint64(packet[5+TxIDLen:5+TxIDLen+8], uint64(time.Now().UnixNano()))
	// Public key
	copy(packet[5+TxIDLen+8:], []byte(e.keyPair.PublicKey))

	if _, err := e.udpConn.WriteToUDP(packet, dst); err != nil {
		return 0, nil, fmt.Errorf("failed to send disco ping: %w", err)
	}

	select {
	case res := <-resCh:
		return res.rtt, res.reflexiveAddr, nil
	case <-time.After(timeout):
		return 0, nil, errors.New("disco ping timed out")
	}
}

// HandlePacket parses incoming discovery UDP packets and auto-replies to Pings with Pongs.
func (e *Engine) HandlePacket(packet []byte, from *net.UDPAddr) (*Message, error) {
	if len(packet) < 5+TxIDLen {
		return nil, ErrPacketShort
	}

	magic := binary.BigEndian.Uint32(packet[0:4])
	if magic != MagicDisco {
		return nil, ErrInvalidMagic
	}

	msgType := packet[4]
	var txID [TxIDLen]byte
	copy(txID[:], packet[5:5+TxIDLen])

	msg := &Message{
		Type: msgType,
		TxID: txID,
	}

	switch msgType {
	case TypePing:
		// Send Pong back echoing txID and observer reflexive address
		e.replyPong(from, txID)
		return msg, nil

	case TypePong:
		e.mu.Lock()
		pending, found := e.pendingPings[txID]
		if found {
			delete(e.pendingPings, txID)
		}
		e.mu.Unlock()

		if found {
			rtt := time.Since(pending.sentAt)
			pending.respCh <- pongResult{
				rtt:           rtt,
				reflexiveAddr: from,
			}
		}
		return msg, nil

	case TypeHeartbeat:
		return msg, nil
	}

	return msg, nil
}

func (e *Engine) replyPong(to *net.UDPAddr, txID [TxIDLen]byte) {
	// Build Pong packet:
	// [4B Magic][1B Type][12B TxID][4B IPv4 / 16B IPv6][2B Port]
	pong := make([]byte, 4+1+TxIDLen+4+2)
	binary.BigEndian.PutUint32(pong[0:4], MagicDisco)
	pong[4] = TypePong
	copy(pong[5:5+TxIDLen], txID[:])

	ip4 := to.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	copy(pong[5+TxIDLen:5+TxIDLen+4], ip4)
	binary.BigEndian.PutUint16(pong[5+TxIDLen+4:5+TxIDLen+6], uint16(to.Port))

	_, _ = e.udpConn.WriteToUDP(pong, to)
}
