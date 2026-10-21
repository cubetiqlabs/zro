// Package overlay abstracts how a daemon accepts and opens TCP connections on
// the overlay: through the host's network stack (kernel TUN) or through an
// in-process userspace stack (netstack mode, no privileges needed).
package overlay

import (
	"context"
	"net"
)

// Network listens and dials on the overlay.
type Network interface {
	// Listen accepts TCP connections addressed to this node's overlay address.
	Listen(port int) (net.Listener, error)
	// DialContext opens a connection to an overlay "ip:port".
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
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
