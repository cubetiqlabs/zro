/* SPDX-License-Identifier: MIT
 *
 * Adapted from golang.zx2c4.com/wireguard/tun/netstack
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package netstack provides a userspace TCP/IP stack behind a WireGuard TUN
// device, so a daemon can run unprivileged (no /dev/net/tun, no routes) and
// still accept and open overlay connections. Unlike the upstream package, the
// overlay address can be added after the device exists, because a node only
// learns its address when it enrolls.
package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const nicID = 1

// Net is the userspace stack; it also implements overlay.Network.
type Net struct {
	ep           *channel.Endpoint
	stack        *stack.Stack
	events       chan tun.Event
	notifyHandle *channel.NotificationHandle
	mtu          int

	mu       sync.Mutex // guards closed and the outbound hand-off
	closed   bool
	outbound chan *buffer.View
	done     chan struct{}
	hasV4    bool
	hasV6    bool
}

// New creates the userspace stack and the TUN device WireGuard drives.
func New(mtu int) (*Device, *Net, error) {
	n := &Net{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			HandleLocal:        true,
		}),
		events:   make(chan tun.Event, 4),
		outbound: make(chan *buffer.View, 256),
		done:     make(chan struct{}),
		mtu:      mtu,
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := n.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, nil, fmt.Errorf("enabling TCP SACK: %v", err)
	}
	n.notifyHandle = n.ep.AddNotify(n)
	if err := n.stack.CreateNIC(nicID, n.ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}
	n.events <- tun.EventUp
	return &Device{n}, n, nil
}

// AddAddress gives the stack an overlay address and routes outbound traffic
// for that family into the device.
func (n *Net) AddAddress(ip netip.Addr) error {
	var proto tcpip.NetworkProtocolNumber
	switch {
	case ip.Is4():
		proto = ipv4.ProtocolNumber
	case ip.Is6():
		proto = ipv6.ProtocolNumber
	default:
		return fmt.Errorf("invalid overlay address %v", ip)
	}
	err := n.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{})
	if err != nil {
		return fmt.Errorf("AddProtocolAddress(%v): %v", ip, err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if ip.Is4() && !n.hasV4 {
		n.hasV4 = true
	} else if ip.Is6() && !n.hasV6 {
		n.hasV6 = true
	} else {
		return nil // the default route for this family is already installed
	}
	n.stack.SetRouteTable(n.routesLocked())
	return nil
}

func (n *Net) routesLocked() []tcpip.Route {
	var routes []tcpip.Route
	if n.hasV4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if n.hasV6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	return routes
}

// Listen accepts TCP connections on every overlay address of the stack.
func (n *Net) Listen(port int) (net.Listener, error) {
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	n.mu.Lock()
	if !n.hasV4 && n.hasV6 {
		proto = ipv6.ProtocolNumber
	}
	n.mu.Unlock()
	return gonet.ListenTCP(n.stack, tcpip.FullAddress{NIC: nicID, Port: uint16(port)}, proto)
}

// DialContext opens a TCP connection to an overlay "ip:port". Names are not
// resolved: the overlay has no resolver, so the host must be an IP literal.
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("netstack: unsupported network %q", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("netstack: %q is not an overlay ip:port: %w", address, err)
	}
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if ap.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{
		NIC: nicID, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port(),
	}, proto)
}

// WriteNotify is called by the link endpoint when the stack has a packet for
// WireGuard.
func (n *Net) WriteNotify() {
	pkt := n.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()

	select {
	case n.outbound <- view:
	case <-n.done:
	}
}

// Device is the tun.Device WireGuard reads from and writes to.
type Device struct{ n *Net }

// DeviceName identifies the device in logs.
func (d *Device) DeviceName() string { return "netstack" }

func (d *Device) Name() (string, error)    { return "netstack", nil }
func (d *Device) File() *os.File           { return nil }
func (d *Device) Events() <-chan tun.Event { return d.n.events }
func (d *Device) MTU() (int, error)        { return d.n.mtu, nil }
func (d *Device) BatchSize() int           { return 1 }
func (d *Device) IsSimulated() bool        { return false }

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case view := <-d.n.outbound:
		n, err := view.Read(bufs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	case <-d.n.done:
		return 0, os.ErrClosed
	}
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			d.n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			d.n.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

func (d *Device) Close() error {
	n := d.n
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	close(n.done) // unblocks Read and any WriteNotify waiting on a full queue
	n.mu.Unlock()

	n.stack.RemoveNIC(nicID)
	n.stack.Close()
	n.ep.RemoveNotify(n.notifyHandle)
	n.ep.Close()
	close(n.events)
	return nil
}
