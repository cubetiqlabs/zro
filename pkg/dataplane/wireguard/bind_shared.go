package wireguard

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const stunMagicCookie = 0x2112A442

// ControlPacketHandler receives UDP datagrams that are not WireGuard protocol
// packets (for example STUN, disco, or hole-punch probes). It is invoked from
// the bind's read loop, so implementations must not block for long.
type ControlPacketHandler func(pkt []byte, from *net.UDPAddr)

type sharedPacket struct {
	data []byte
	from *net.UDPAddr
}

// sharedBind implements conn.Bind on top of a caller-owned UDP socket. This
// lets WireGuard, STUN, discovery, and hole punching share one NAT mapping:
// the port peers observe is the same port WireGuard actually receives on.
type sharedBind struct {
	conn    *net.UDPConn
	handler ControlPacketHandler

	mu     sync.Mutex
	open   bool
	closed chan struct{}
	recvCh chan sharedPacket
	loopWG sync.WaitGroup
}

func newSharedBind(udpConn *net.UDPConn, handler ControlPacketHandler) *sharedBind {
	return &sharedBind{
		conn:    udpConn,
		handler: handler,
	}
}

// Open starts the single read loop that owns the shared socket.
func (b *sharedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true
	b.closed = make(chan struct{})
	b.recvCh = make(chan sharedPacket, 512)
	closed := b.closed
	recvCh := b.recvCh
	b.loopWG.Add(1)
	b.mu.Unlock()

	local, ok := b.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		b.mu.Lock()
		b.open = false
		b.mu.Unlock()
		return nil, 0, net.InvalidAddrError("shared bind requires a UDP address")
	}

	go b.readLoop(closed, recvCh)

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case pkt, ok := <-recvCh:
			if !ok {
				return 0, net.ErrClosed
			}
			if len(bufs) == 0 {
				return 0, nil
			}
			n := copy(bufs[0], pkt.data)
			sizes[0] = n
			if len(eps) > 0 {
				eps[0] = &sharedEndpoint{addr: pkt.from}
			}
			return 1, nil
		}
	}

	return []conn.ReceiveFunc{recv}, uint16(local.Port), nil
}

func (b *sharedBind) readLoop(closed <-chan struct{}, recvCh chan<- sharedPacket) {
	defer b.loopWG.Done()

	// Clear any deadline left by a previous Close. Close wakes this loop by
	// setting an immediate deadline, so no polling is needed.
	_ = b.conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 65535)
	for {
		select {
		case <-closed:
			return
		default:
		}

		n, from, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-closed:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// The caller-owned socket was closed or is unusable; stop the loop.
			// ReceiveFuncs still unblock when Close closes the bind.
			return
		}
		if n == 0 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		if IsWireGuardPacket(pkt) {
			select {
			case recvCh <- sharedPacket{data: pkt, from: from}:
			default:
				// WireGuard retransmits; drop rather than block the socket.
			}
			continue
		}

		if b.handler != nil {
			b.handler(pkt, from)
		}
	}
}

// Close stops the read loop. The underlying UDP socket is owned by the caller
// and is deliberately left open.
func (b *sharedBind) Close() error {
	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		return nil
	}
	b.open = false
	close(b.closed)
	// Wake the read loop immediately instead of waiting for its poll deadline.
	_ = b.conn.SetReadDeadline(time.Now())
	b.mu.Unlock()

	b.loopWG.Wait()
	return nil
}

// SetMark is a no-op for the shared socket.
func (b *sharedBind) SetMark(mark uint32) error { return nil }

// Send writes datagrams to the endpoint through the shared socket.
func (b *sharedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	se, ok := ep.(*sharedEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDP(buf, se.addr); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint converts "host:port" into a shared endpoint.
func (b *sharedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &sharedEndpoint{addr: net.UDPAddrFromAddrPort(addrPort)}, nil
}

// BatchSize keeps the shared bind simple; WireGuard handles one datagram at a time.
func (b *sharedBind) BatchSize() int { return 1 }

type sharedEndpoint struct {
	addr *net.UDPAddr
}

func (e *sharedEndpoint) ClearSrc() {}

func (e *sharedEndpoint) SrcToString() string { return "" }

func (e *sharedEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (e *sharedEndpoint) DstToString() string { return e.addr.String() }

func (e *sharedEndpoint) DstToBytes() []byte {
	ip, ok := netip.AddrFromSlice(e.addr.IP)
	if !ok {
		return nil
	}
	addrPort := netip.AddrPortFrom(ip.Unmap(), uint16(e.addr.Port))
	raw, _ := addrPort.MarshalBinary()
	return raw
}

func (e *sharedEndpoint) DstIP() netip.Addr {
	ip, ok := netip.AddrFromSlice(e.addr.IP)
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// IsWireGuardPacket reports whether a datagram is a WireGuard protocol message.
// Message layouts are fixed by the WireGuard protocol:
//   - handshake initiation: 148 bytes, type 1
//   - handshake response:    92 bytes, type 2
//   - cookie reply:          64 bytes, type 3
//   - transport data:    >= 32 bytes, type 4, 16-byte aligned
func IsWireGuardPacket(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	// STUN uses a fixed magic cookie. Check it first so a large STUN message
	// with a type-1 first byte cannot be mistaken for a handshake initiation.
	if len(pkt) >= 20 && binary.BigEndian.Uint32(pkt[4:8]) == stunMagicCookie {
		return false
	}
	switch pkt[0] {
	case 1:
		return len(pkt) == 148
	case 2:
		return len(pkt) == 92
	case 3:
		return len(pkt) == 64
	case 4:
		return len(pkt) >= 32 && len(pkt)%16 == 0
	default:
		return false
	}
}
