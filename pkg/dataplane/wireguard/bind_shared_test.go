package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/tun"
)

func TestIsWireGuardPacket(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"empty", nil, false},
		{"handshake initiation", append([]byte{1}, make([]byte, 147)...), true},
		{"handshake response", append([]byte{2}, make([]byte, 91)...), true},
		{"cookie reply", append([]byte{3}, make([]byte, 63)...), true},
		{"transport data", append([]byte{4}, make([]byte, 47)...), true},
		{"wrong initiation length", append([]byte{1}, make([]byte, 20)...), false},
		{"unaligned transport", append([]byte{4}, make([]byte, 20)...), false},
		{"stun request", append([]byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}, make([]byte, 12)...), false},
		{"large stun response", func() []byte {
			pkt := make([]byte, 148)
			binary.BigEndian.PutUint16(pkt[0:2], 0x0101)
			binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442)
			return pkt
		}(), false},
		{"puncher ping", []byte("ZRO_P2P_PING_V1"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWireGuardPacket(tt.pkt); got != tt.want {
				t.Fatalf("IsWireGuardPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSharedSocketDeliversOverLoopback proves the full userspace path:
// packet injected into TUN A -> WireGuard -> shared UDP socket -> WireGuard B
// -> TUN B. It would fail if STUN and WireGuard used different sockets, or if
// the userspace device never opened its bind.
func TestSharedSocketDeliversOverLoopback(t *testing.T) {
	kpA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair A: %v", err)
	}
	kpB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair B: %v", err)
	}

	sockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer sockA.Close()
	sockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer sockB.Close()

	devA := tun.NewMemoryDevice("wg-loop-a", 1420)
	defer devA.Close()
	devB := tun.NewMemoryDevice("wg-loop-b", 1420)
	defer devB.Close()

	mgrA, err := NewManager("wg-loop-a",
		WithTunDevice(devA),
		WithPrivateKey(kpA.PrivateKey),
		WithSharedSocket(sockA, nil),
	)
	if err != nil {
		t.Fatalf("manager A: %v", err)
	}
	defer mgrA.Close()

	mgrB, err := NewManager("wg-loop-b",
		WithTunDevice(devB),
		WithPrivateKey(kpB.PrivateKey),
		WithSharedSocket(sockB, nil),
	)
	if err != nil {
		t.Fatalf("manager B: %v", err)
	}
	defer mgrB.Close()

	addrA := sockA.LocalAddr().(*net.UDPAddr)
	addrB := sockB.LocalAddr().(*net.UDPAddr)

	if err := mgrA.ApplyPeer(PeerConfig{
		PublicKey:  kpB.PublicKey,
		Endpoint:   addrB.String(),
		AllowedIPs: []string{"100.64.0.2/32"},
	}); err != nil {
		t.Fatalf("apply peer A->B: %v", err)
	}
	if err := mgrB.ApplyPeer(PeerConfig{
		PublicKey:  kpA.PublicKey,
		Endpoint:   addrA.String(),
		AllowedIPs: []string{"100.64.0.1/32"},
	}); err != nil {
		t.Fatalf("apply peer B->A: %v", err)
	}

	packet := ipv4Packet(t, "100.64.0.1", "100.64.0.2", []byte("zro-mesh"))
	if err := devA.InjectPacket(packet); err != nil {
		t.Fatalf("inject packet: %v", err)
	}

	type result struct {
		pkt []byte
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		pkt, err := devB.EjectPacket()
		resultCh <- result{pkt: pkt, err: err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("eject packet: %v", res.err)
		}
		if !bytes.Equal(res.pkt, packet) {
			t.Fatalf("payload mismatch:\n got %x\nwant %x", res.pkt, packet)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for packet to traverse WireGuard loopback")
	}
}

func TestSharedSocketDispatchesControlPackets(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	serverSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer serverSock.Close()

	dev := tun.NewMemoryDevice("wg-dispatch", 1420)
	defer dev.Close()

	handled := make(chan string, 1)
	mgr, err := NewManager("wg-dispatch",
		WithTunDevice(dev),
		WithPrivateKey(kp.PrivateKey),
		WithSharedSocket(serverSock, func(pkt []byte, from *net.UDPAddr) {
			if string(pkt) == "control-ping" {
				_, _ = serverSock.WriteToUDP([]byte("control-pong"), from)
				handled <- string(pkt)
			}
		}),
	)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer mgr.Close()

	clientSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientSock.Close()

	if _, err := clientSock.WriteToUDP([]byte("control-ping"), serverSock.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send control packet: %v", err)
	}

	select {
	case pkt := <-handled:
		if pkt != "control-ping" {
			t.Fatalf("handler saw %q", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control packet was not dispatched to the handler")
	}

	_ = clientSock.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := clientSock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read control response: %v", err)
	}
	if string(buf[:n]) != "control-pong" {
		t.Fatalf("unexpected control response %q", buf[:n])
	}
}

// TestSharedSocketRelaysThroughEdge proves the relay path at the packet level:
// node A -> edge WireGuard -> re-injected into the edge TUN (kernel forwarding
// stand-in) -> edge WireGuard -> node B. It validates that an Edge PoP with a
// userspace WireGuard device can decrypt, forward, and re-encrypt overlay
// traffic between two peers.
func TestSharedSocketRelaysThroughEdge(t *testing.T) {
	kpA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair A: %v", err)
	}
	kpB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair B: %v", err)
	}
	kpE, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair edge: %v", err)
	}

	newSock := func() *net.UDPConn {
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		return sock
	}
	sockA, sockB, sockE := newSock(), newSock(), newSock()
	defer sockA.Close()
	defer sockB.Close()
	defer sockE.Close()

	devA := tun.NewMemoryDevice("relay-a", 1420)
	devB := tun.NewMemoryDevice("relay-b", 1420)
	devE := tun.NewMemoryDevice("relay-edge", 1420)
	defer devA.Close()
	defer devB.Close()
	defer devE.Close()

	newMgr := func(name, key string, dev tun.Device, sock *net.UDPConn) *Manager {
		mgr, err := NewManager(name,
			WithTunDevice(dev),
			WithPrivateKey(key),
			WithSharedSocket(sock, nil),
		)
		if err != nil {
			t.Fatalf("manager %s: %v", name, err)
		}
		return mgr
	}
	mgrA := newMgr("relay-a", kpA.PrivateKey, devA, sockA)
	mgrB := newMgr("relay-b", kpB.PrivateKey, devB, sockB)
	mgrE := newMgr("relay-edge", kpE.PrivateKey, devE, sockE)
	defer mgrA.Close()
	defer mgrB.Close()
	defer mgrE.Close()

	addrA := sockA.LocalAddr().(*net.UDPAddr).String()
	addrB := sockB.LocalAddr().(*net.UDPAddr).String()
	addrE := sockE.LocalAddr().(*net.UDPAddr).String()

	// Nodes send all overlay traffic to the Edge; the Edge maps each /32 to the
	// owning peer.
	if err := mgrA.ApplyPeer(PeerConfig{PublicKey: kpE.PublicKey, Endpoint: addrE, AllowedIPs: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatalf("A->edge peer: %v", err)
	}
	if err := mgrB.ApplyPeer(PeerConfig{PublicKey: kpE.PublicKey, Endpoint: addrE, AllowedIPs: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatalf("B->edge peer: %v", err)
	}
	if err := mgrE.ApplyPeer(PeerConfig{PublicKey: kpA.PublicKey, Endpoint: addrA, AllowedIPs: []string{"100.64.0.1/32"}}); err != nil {
		t.Fatalf("edge->A peer: %v", err)
	}
	if err := mgrE.ApplyPeer(PeerConfig{PublicKey: kpB.PublicKey, Endpoint: addrB, AllowedIPs: []string{"100.64.0.2/32"}}); err != nil {
		t.Fatalf("edge->B peer: %v", err)
	}

	packet := ipv4Packet(t, "100.64.0.1", "100.64.0.2", []byte("relay-through-edge"))
	if err := devA.InjectPacket(packet); err != nil {
		t.Fatalf("inject at A: %v", err)
	}

	atEdge := waitForPacket(t, devE, 8*time.Second, "edge ingress")
	if !bytes.Equal(atEdge, packet) {
		t.Fatalf("edge received modified packet:\n got %x\nwant %x", atEdge, packet)
	}

	// Stand in for the kernel forwarding step: send the packet back into the
	// edge TUN, where WireGuard selects the peer by destination /32.
	if err := devE.InjectPacket(atEdge); err != nil {
		t.Fatalf("reinject at edge: %v", err)
	}

	atB := waitForPacket(t, devB, 8*time.Second, "node B egress")
	if !bytes.Equal(atB, packet) {
		t.Fatalf("node B received modified packet:\n got %x\nwant %x", atB, packet)
	}
}

func waitForPacket(t *testing.T, dev *tun.MemoryDevice, timeout time.Duration, label string) []byte {
	t.Helper()
	type result struct {
		pkt []byte
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		pkt, err := dev.EjectPacket()
		resultCh <- result{pkt: pkt, err: err}
	}()
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("%s: %v", label, res.err)
		}
		return res.pkt
	case <-time.After(timeout):
		t.Fatalf("%s: timed out", label)
		return nil
	}
}

func ipv4Packet(t *testing.T, src, dst string, payload []byte) []byte {
	t.Helper()
	srcIP := net.ParseIP(src).To4()
	dstIP := net.ParseIP(dst).To4()
	if srcIP == nil || dstIP == nil {
		t.Fatalf("invalid IPv4 address pair %q -> %q", src, dst)
	}

	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // IPv4, header length 5 words
	pkt[1] = 0
	total := len(pkt)
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[4] = 0 // ID
	pkt[5] = 0
	pkt[6] = 0 // flags/fragment
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = 1  // ICMP
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	copy(pkt[20:], payload)
	return pkt
}
