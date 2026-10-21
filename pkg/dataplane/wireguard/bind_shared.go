package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/dataplane/relay"
	"golang.zx2c4.com/wireguard/conn"
)

const stunMagicCookie = 0x2112A442

// ControlPacketHandler receives UDP datagrams that are not WireGuard protocol
// packets (for example STUN, disco, or hole-punch probes). It is invoked from
// the bind's read loop, so implementations must not block for long.
type ControlPacketHandler func(pkt []byte, from *net.UDPAddr)

type sharedPacket struct {
	data     []byte
	from     *net.UDPAddr
	relaySrc *[relay.KeyLen]byte // set when the datagram arrived through the relay
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

	relay relay.Transport // optional fallback path; guarded by mu
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
	if b.relay != nil {
		b.startPumpLocked(b.relay)
	}
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
				if pkt.relaySrc != nil {
					eps[0] = &relayEndpoint{key: *pkt.relaySrc}
				} else {
					eps[0] = &sharedEndpoint{addr: pkt.from}
				}
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
	if re, ok := ep.(*relayEndpoint); ok {
		b.mu.Lock()
		t := b.relay
		b.mu.Unlock()
		if t == nil {
			return errNoRelay
		}
		for _, buf := range bufs {
			if err := t.Send(re.key, buf); err != nil {
				return err
			}
		}
		return nil
	}
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
	if enc, ok := strings.CutPrefix(s, relayScheme); ok {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil || len(raw) != relay.KeyLen {
			return nil, fmt.Errorf("invalid relay endpoint %q", s)
		}
		var key [relay.KeyLen]byte
		copy(key[:], raw)
		return &relayEndpoint{key: key}, nil
	}
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

// relayScheme prefixes endpoints that reach a peer through the relay:
// "derp:<base64 public key>".
const relayScheme = "derp:"

var errNoRelay = errors.New("no relay transport attached")

// RelayEndpoint returns the endpoint string that routes a peer's traffic
// through the relay, for use in PeerConfig.Endpoint.
func RelayEndpoint(peerPubKey string) string { return relayScheme + peerPubKey }

// AttachRelay installs the relay used for peers whose endpoint is a relay
// endpoint. It may be called before or after the bind opens, and again to
// replace a transport that ended.
func (b *sharedBind) AttachRelay(t relay.Transport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relay = t
	if b.open {
		b.startPumpLocked(t)
	}
}

// DetachRelay removes t if it is still the attached transport.
func (b *sharedBind) DetachRelay(t relay.Transport) {
	b.mu.Lock()
	if b.relay == t {
		b.relay = nil
	}
	b.mu.Unlock()
}

// startPumpLocked forwards the relay's datagrams into WireGuard's receive
// queue. b.mu must be held and the bind open.
func (b *sharedBind) startPumpLocked(t relay.Transport) {
	closed, recvCh := b.closed, b.recvCh
	b.loopWG.Add(1)
	go func() {
		defer b.loopWG.Done()
		in := t.Recv()
		for {
			select {
			case <-closed:
				return
			case p, ok := <-in:
				if !ok {
					b.DetachRelay(t)
					return
				}
				if !IsWireGuardPacket(p.Payload) {
					continue // the relay only carries WireGuard traffic
				}
				src := p.SrcPubKey
				select {
				case recvCh <- sharedPacket{data: p.Payload, relaySrc: &src}:
				default:
				}
			}
		}
	}()
}

// relayEndpoint addresses a peer by public key through the relay.
type relayEndpoint struct {
	key [relay.KeyLen]byte
}

func (e *relayEndpoint) ClearSrc()           {}
func (e *relayEndpoint) SrcToString() string { return "" }
func (e *relayEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *relayEndpoint) DstToString() string {
	return relayScheme + base64.StdEncoding.EncodeToString(e.key[:])
}
func (e *relayEndpoint) DstToBytes() []byte { return e.key[:] }

// DstIP is a stable synthetic address (unique local range) so WireGuard's
// per-source handshake rate limiter keeps relay peers apart.
func (e *relayEndpoint) DstIP() netip.Addr {
	var a [16]byte
	a[0], a[1] = 0xfd, 0xde
	copy(a[2:], e.key[:14])
	return netip.AddrFrom16(a)
}
