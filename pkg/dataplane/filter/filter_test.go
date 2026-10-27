package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN records what reaches the OS and serves queued packets to Read.
type fakeTUN struct {
	tun.Device
	delivered [][]byte
	queued    [][]byte
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.delivered = append(f.delivered, bufs...)
	return len(bufs), nil
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	sizes[0] = copy(bufs[0][offset:], f.queued[0])
	f.queued = f.queued[1:]
	return 1, nil
}

func (f *fakeTUN) Close() error { return nil }

var (
	me   = netip.MustParseAddr("100.64.0.2")
	peer = netip.MustParseAddr("100.64.0.3")
)

// ip4 builds an IPv4 packet; l4 starts with ports (TCP/UDP) or type/code (ICMP).
func ip4(proto uint8, src, dst netip.Addr, l4 []byte) []byte {
	p := make([]byte, 20, 20+len(l4))
	p[0] = 0x45
	p[9] = proto
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	return append(p, l4...)
}

func tcp(sport, dport uint16) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	return l4
}

func icmp(typ uint8, id uint16) []byte {
	l4 := make([]byte, 8)
	l4[0] = typ
	binary.BigEndian.PutUint16(l4[4:6], id)
	return l4
}

func TestFilter(t *testing.T) {
	mem := &fakeTUN{}
	// Policy: only TCP 22 and ping are open.
	f := Wrap(mem, func(p Packet) bool { return (p.Proto == ProtoTCP && p.DstPort == 22) || p.Echo })
	defer f.Close()

	in := func(pkt []byte) bool {
		before := len(mem.delivered)
		_, _ = f.Write([][]byte{pkt}, 0)
		return len(mem.delivered) > before
	}
	out := func(pkt []byte) {
		mem.queued = append(mem.queued, pkt)
		bufs, sizes := [][]byte{make([]byte, 1500)}, []int{0}
		_, _ = f.Read(bufs, sizes, 0)
	}

	if !in(ip4(ProtoTCP, peer, me, tcp(40000, 22))) {
		t.Error("allowed port dropped")
	}
	if in(ip4(ProtoTCP, peer, me, tcp(40000, 5432))) {
		t.Error("closed port admitted")
	}
	if !in(ip4(ProtoICMP, peer, me, icmp(8, 7))) {
		t.Error("ping dropped")
	}
	if !in(ip4(ProtoICMP, peer, me, icmp(3, 0))) {
		t.Error("ICMP unreachable dropped")
	}

	// A reply to a connection this node opened gets in on a closed port.
	if in(ip4(ProtoTCP, peer, me, tcp(443, 50000))) {
		t.Fatal("unsolicited packet admitted")
	}
	out(ip4(ProtoTCP, me, peer, tcp(50000, 443)))
	if !in(ip4(ProtoTCP, peer, me, tcp(443, 50000))) {
		t.Error("reply to an outbound flow dropped")
	}
	if in(ip4(ProtoUDP, peer, me, tcp(443, 50000))) {
		t.Error("a UDP packet matched a TCP flow")
	}

	// Mixed batch: only the allowed packet reaches the OS.
	before := len(mem.delivered)
	_, _ = f.Write([][]byte{ip4(ProtoTCP, peer, me, tcp(1, 5432)), ip4(ProtoTCP, peer, me, tcp(1, 22))}, 0)
	if got := len(mem.delivered) - before; got != 1 {
		t.Errorf("batch: %d packets delivered, want 1", got)
	}
}

func BenchmarkEstablished(b *testing.B) {
	f := Wrap(&fakeTUN{}, func(Packet) bool { return false })
	defer f.Close()
	f.touch(flowKey{proto: ProtoTCP, local: me, remote: peer, localPort: 50000, remotePort: 443}, 1)
	pkt := ip4(ProtoTCP, peer, me, tcp(443, 50000))
	b.ReportAllocs()
	for b.Loop() {
		if !f.admit(pkt) {
			b.Fatal("dropped")
		}
	}
}
