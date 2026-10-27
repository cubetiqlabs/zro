// Package filter is the node's stateful inbound firewall. It wraps the device
// WireGuard drives, so the same code enforces policy for a kernel TUN and for
// the userspace stack, with no OS firewall involved.
//
// Packets the node sends record a flow; replies to a recorded flow are let in.
// Every other inbound packet is put to the Allow callback once per flow.
package filter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// IP protocol numbers the filter understands.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

const (
	tcpIdle    = 5 * time.Minute
	otherIdle  = 30 * time.Second
	sweepEvery = 30 * time.Second
	tick       = time.Second // resolution of the flow clock
)

// Packet is the part of an inbound packet the policy decides on.
type Packet struct {
	Src, Dst netip.Addr
	Proto    uint8
	DstPort  uint16 // 0 for ICMP
	Echo     bool   // ICMP echo request
}

// Protocol returns the policy name of the protocol ("tcp", "udp", "icmp").
func (p Packet) Protocol() string {
	switch p.Proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP, ProtoICMPv6:
		return "icmp"
	}
	return ""
}

type flowKey struct {
	proto                 uint8
	local, remote         netip.Addr
	localPort, remotePort uint16 // ICMP: the echo identifier in both
}

// Device drops inbound packets the policy does not allow.
type Device struct {
	tun.Device
	allow func(Packet) bool

	mu    sync.RWMutex
	flows map[flowKey]*atomic.Int64 // last seen, unix nanos
	now   atomic.Int64              // coarse clock: time.Now per packet costs more than the lookup
	stop  chan struct{}
	once  sync.Once
}

// Wrap returns dev with allow applied to every new inbound flow.
func Wrap(dev tun.Device, allow func(Packet) bool) *Device {
	d := &Device{Device: dev, allow: allow, flows: make(map[flowKey]*atomic.Int64), stop: make(chan struct{})}
	d.now.Store(time.Now().UnixNano())
	go d.sweeper()
	return d
}

// Read hands WireGuard what the OS sends, recording each packet's flow.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	now := d.now.Load()
	for i := 0; i < n; i++ {
		if k, ok := outboundKey(bufs[i][offset : offset+sizes[i]]); ok {
			d.touch(k, now)
		}
	}
	return n, err
}

// Write delivers what WireGuard decrypted, minus the packets policy rejects.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	var kept [][]byte // stays nil while every packet is admitted
	for i, b := range bufs {
		if d.admit(b[offset:]) {
			if kept != nil {
				kept = append(kept, b)
			}
			continue
		}
		if kept == nil {
			kept = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if kept == nil {
		kept = bufs
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	if _, err := d.Device.Write(kept, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (d *Device) Close() error {
	d.once.Do(func() { close(d.stop) })
	return d.Device.Close()
}

func (d *Device) admit(pkt []byte) bool {
	p, reply, ok := parseInbound(pkt)
	if !ok {
		return false
	}
	if p.Proto == 0 {
		return true // non-first fragment: its first fragment was already judged
	}
	if reply.proto != 0 {
		d.mu.RLock()
		last := d.flows[reply]
		d.mu.RUnlock()
		if last != nil {
			last.Store(d.now.Load())
			return true
		}
	}
	if isICMPError(pkt) {
		return true // unreachable / time exceeded / too big: needed for PMTU and fast failure
	}
	if !d.allow(p) {
		return false
	}
	// Remember the allowed flow so the rest of it skips the policy.
	if reply.proto != 0 {
		d.touch(reply, d.now.Load())
	}
	return true
}

func (d *Device) touch(k flowKey, now int64) {
	d.mu.RLock()
	last := d.flows[k]
	d.mu.RUnlock()
	if last == nil {
		d.mu.Lock()
		if last = d.flows[k]; last == nil {
			last = new(atomic.Int64)
			d.flows[k] = last
		}
		d.mu.Unlock()
	}
	last.Store(now)
}

// ponytail: one RWMutex over the flow map; shard it if contention shows up in profiles.
func (d *Device) sweeper() {
	t := time.NewTicker(tick)
	defer t.Stop()
	lastSweep := time.Now()
	for {
		select {
		case <-d.stop:
			return
		case now := <-t.C:
			d.now.Store(now.UnixNano())
			if now.Sub(lastSweep) < sweepEvery {
				continue
			}
			lastSweep = now
			d.mu.Lock()
			for k, last := range d.flows {
				idle := otherIdle
				if k.proto == ProtoTCP {
					idle = tcpIdle
				}
				if now.UnixNano()-last.Load() > int64(idle) {
					delete(d.flows, k)
				}
			}
			d.mu.Unlock()
		}
	}
}

// header returns the protocol, addresses and L4 payload of an IP packet.
// proto is 0 for a non-first fragment.
func header(pkt []byte) (proto uint8, src, dst netip.Addr, l4 []byte, ok bool) {
	if len(pkt) < 1 {
		return 0, src, dst, nil, false
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 || len(pkt) < ihl {
			return 0, src, dst, nil, false
		}
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return 0, src, dst, nil, true
		}
		return pkt[9], src, dst, pkt[ihl:], true
	case 6:
		if len(pkt) < 40 {
			return 0, src, dst, nil, false
		}
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		// ponytail: extension headers are not walked; such packets are judged by
		// their next-header value with no port, so policy can still deny them.
		return pkt[6], src, dst, pkt[40:], true
	}
	return 0, src, dst, nil, false
}

// ports returns the source and destination ports (ICMP echo: the identifier as
// both) and whether the packet is an ICMP echo request.
func ports(proto uint8, l4 []byte) (sport, dport uint16, echoReq, echoAny bool) {
	switch proto {
	case ProtoTCP, ProtoUDP:
		if len(l4) >= 4 {
			return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4]), false, false
		}
	case ProtoICMP, ProtoICMPv6:
		if len(l4) >= 8 {
			id := binary.BigEndian.Uint16(l4[4:6])
			t := l4[0]
			req := (proto == ProtoICMP && t == 8) || (proto == ProtoICMPv6 && t == 128)
			rep := (proto == ProtoICMP && t == 0) || (proto == ProtoICMPv6 && t == 129)
			return id, id, req, req || rep
		}
	}
	return 0, 0, false, false
}

func outboundKey(pkt []byte) (flowKey, bool) {
	proto, src, dst, l4, ok := header(pkt)
	if !ok || proto == 0 {
		return flowKey{}, false
	}
	sport, dport, _, echo := ports(proto, l4)
	if (proto == ProtoICMP || proto == ProtoICMPv6) && !echo {
		return flowKey{}, false
	}
	return flowKey{proto: proto, local: src, remote: dst, localPort: sport, remotePort: dport}, true
}

// parseInbound returns the policy view of the packet and the key its flow would
// have been recorded under (zero when the packet has no flow, like ICMP errors).
func parseInbound(pkt []byte) (Packet, flowKey, bool) {
	proto, src, dst, l4, ok := header(pkt)
	if !ok {
		return Packet{}, flowKey{}, false
	}
	p := Packet{Src: src, Dst: dst, Proto: proto}
	if proto == 0 {
		return p, flowKey{}, true
	}
	sport, dport, echoReq, echo := ports(proto, l4)
	p.Echo = echoReq
	if proto == ProtoTCP || proto == ProtoUDP {
		p.DstPort = dport
	}
	var k flowKey
	if proto == ProtoTCP || proto == ProtoUDP || echo {
		k = flowKey{proto: proto, local: dst, remote: src, localPort: dport, remotePort: sport}
	}
	return p, k, true
}

func isICMPError(pkt []byte) bool {
	proto, _, _, l4, ok := header(pkt)
	if !ok || len(l4) < 1 {
		return false
	}
	switch proto {
	case ProtoICMP:
		return l4[0] == 3 || l4[0] == 11 || l4[0] == 12
	case ProtoICMPv6:
		return l4[0] >= 1 && l4[0] <= 4
	}
	return false
}
