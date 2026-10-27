// Package overlay abstracts how a daemon accepts and opens TCP connections on
// the overlay: through the host's network stack (kernel TUN) or through an
// in-process userspace stack (netstack mode, no privileges needed).
package overlay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Network listens and dials on the overlay.
type Network interface {
	// Listen accepts TCP connections addressed to this node's overlay address.
	Listen(port int) (net.Listener, error)
	// DialContext opens a connection to an overlay "ip:port".
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Ping sends one ICMP echo to an overlay IPv4 address and returns the RTT.
	Ping(ctx context.Context, ip netip.Addr) (time.Duration, error)
}

// Host is the Network of a kernel TUN device: the OS routes overlay addresses
// into the interface, so ordinary sockets work.
type Host struct {
	// IP returns this node's overlay address (known only after enrollment).
	IP func() string
}

// Listen binds the overlay address, so the socket is reachable only through
// the tunnel and never on other interfaces.
func (h Host) Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort(h.IP(), itoa(port)))
}

// DialContext dials through the host stack.
func (Host) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Ping uses a raw ICMP socket; kernel-mode agents run as root.
func (h Host) Ping(ctx context.Context, ip netip.Addr) (time.Duration, error) {
	if !ip.Is4() {
		return 0, errors.New("ping supports IPv4 only")
	}
	c, err := icmp.ListenPacket("ip4:icmp", h.IP())
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	id := os.Getpid() & 0xffff
	msg, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("zro")}}).Marshal(nil)
	start := time.Now()
	if _, err := c.WriteTo(msg, &net.IPAddr{IP: ip.AsSlice()}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply || from.String() != ip.String() {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
			return time.Since(start), nil
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for ; n > 0; n /= 10 {
		i--
		b[i] = byte('0' + n%10)
	}
	return string(b[i:])
}
