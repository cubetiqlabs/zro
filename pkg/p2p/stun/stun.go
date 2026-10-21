package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	MagicCookie          = 0x2112A442
	BindingRequest       = 0x0001
	BindingResponse      = 0x0101
	AttrXORMappedAddress = 0x0020
)

// ReflexiveAddress holds public IP and port discovered via STUN.
type ReflexiveAddress struct {
	IP   net.IP
	Port int
}

func (r ReflexiveAddress) String() string {
	return net.JoinHostPort(r.IP.String(), fmt.Sprintf("%d", r.Port))
}

// NewBindingRequest builds an RFC 5389 STUN Binding Request and returns the
// transaction ID used to correlate the response.
func NewBindingRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, fmt.Errorf("failed to generate STUN transaction ID: %w", err)
	}

	// 20-byte header: 2B type, 2B length, 4B magic cookie, 12B transaction ID.
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], BindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // zero attributes
	binary.BigEndian.PutUint32(req[4:8], MagicCookie)
	copy(req[8:20], txID[:])
	return req, txID, nil
}

// IsBindingResponse reports whether packet is a STUN Binding Response.
func IsBindingResponse(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	return binary.BigEndian.Uint16(packet[0:2]) == BindingResponse &&
		binary.BigEndian.Uint32(packet[4:8]) == MagicCookie
}

// IsBindingRequest reports whether packet is a STUN Binding Request.
func IsBindingRequest(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	return binary.BigEndian.Uint16(packet[0:2]) == BindingRequest &&
		binary.BigEndian.Uint32(packet[4:8]) == MagicCookie
}

// ParseResponse decodes a STUN Binding Response and verifies its transaction ID.
func ParseResponse(packet []byte, txID []byte) (*ReflexiveAddress, error) {
	return parseSTUNResponse(packet, txID)
}

// DiscoverPublicEndpoint contacts a STUN server (such as an Edge PoP) to discover the client's public reflexive address.
// It performs a synchronous read on localConn and must not be called on a socket owned by the WireGuard bind.
func DiscoverPublicEndpoint(localConn *net.UDPConn, serverAddr string, timeout time.Duration) (*ReflexiveAddress, error) {
	srv, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server: %w", err)
	}

	req, txID, err := NewBindingRequest()
	if err != nil {
		return nil, err
	}

	_ = localConn.SetDeadline(time.Now().Add(timeout))
	defer localConn.SetDeadline(time.Time{})

	if _, err := localConn.WriteToUDP(req, srv); err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	buf := make([]byte, 512)
	n, _, err := localConn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	return parseSTUNResponse(buf[:n], txID[:])
}

// ProbeEndpoint contacts a STUN server (such as an Edge PoP) to measure round-trip latency (RTT)
// and reflexively discover the client's public NAT address.
func ProbeEndpoint(serverAddr string, timeout time.Duration) (time.Duration, *ReflexiveAddress, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to bind ephemeral probe socket: %w", err)
	}
	defer conn.Close()

	start := time.Now()
	addr, err := DiscoverPublicEndpoint(conn, serverAddr, timeout)
	if err != nil {
		return 0, nil, err
	}
	rtt := time.Since(start)
	return rtt, addr, nil
}

// ServeSTUN runs a lightweight STUN responder on an incoming UDP connection.
func ServeSTUN(conn *net.UDPConn, packet []byte, clientAddr *net.UDPAddr) error {
	if len(packet) < 20 {
		return errors.New("packet too small for STUN")
	}

	msgType := binary.BigEndian.Uint16(packet[0:2])
	if msgType != BindingRequest {
		return nil // ignore non-binding requests
	}

	// Build STUN Binding Success Response
	txID := packet[8:20]
	resp := make([]byte, 32)
	binary.BigEndian.PutUint16(resp[0:2], BindingResponse)
	binary.BigEndian.PutUint16(resp[2:4], 12) // Attribute length: 12 bytes
	binary.BigEndian.PutUint32(resp[4:8], MagicCookie)
	copy(resp[8:20], txID)

	// XOR-MAPPED-ADDRESS attribute (Type 0x0020, Length 8 for IPv4)
	binary.BigEndian.PutUint16(resp[20:22], AttrXORMappedAddress)
	binary.BigEndian.PutUint16(resp[22:24], 8)
	resp[24] = 0 // reserved
	resp[25] = 1 // IPv4 family

	// XOR Port
	xorPort := uint16(clientAddr.Port) ^ uint16(MagicCookie>>16)
	binary.BigEndian.PutUint16(resp[26:28], xorPort)

	// XOR IPv4
	ip4 := clientAddr.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	xorIP := binary.BigEndian.Uint32(ip4) ^ MagicCookie
	binary.BigEndian.PutUint32(resp[28:32], xorIP)

	_, err := conn.WriteToUDP(resp, clientAddr)
	return err
}

func parseSTUNResponse(buf []byte, originalTxID []byte) (*ReflexiveAddress, error) {
	if len(buf) < 20 {
		return nil, errors.New("truncated STUN response")
	}

	msgType := binary.BigEndian.Uint16(buf[0:2])
	if msgType != BindingResponse {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%04x", msgType)
	}

	cookie := binary.BigEndian.Uint32(buf[4:8])
	if cookie != MagicCookie {
		return nil, errors.New("invalid STUN magic cookie")
	}

	if len(originalTxID) != 12 {
		return nil, errors.New("invalid STUN transaction ID length")
	}
	if !bytes.Equal(buf[8:20], originalTxID) {
		return nil, errors.New("STUN transaction ID mismatch")
	}

	attrs := buf[20:]
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(attrs) {
			break
		}

		if attrType == AttrXORMappedAddress && attrLen >= 8 {
			family := attrs[offset+1]
			if family == 1 { // IPv4
				xorPort := binary.BigEndian.Uint16(attrs[offset+2 : offset+4])
				port := int(xorPort ^ uint16(MagicCookie>>16))

				xorIP := binary.BigEndian.Uint32(attrs[offset+4 : offset+8])
				ipVal := xorIP ^ MagicCookie
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, ipVal)

				return &ReflexiveAddress{IP: ip, Port: port}, nil
			}
		}

		offset += attrLen
	}

	return nil, errors.New("no XOR-MAPPED-ADDRESS found in STUN response")
}
