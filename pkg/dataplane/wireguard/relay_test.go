package wireguard

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/dataplane/derp"
	"github.com/cubetiqlabs/zro/pkg/dataplane/tun"
)

type side struct {
	kp  *crypto.KeyPair
	dev *tun.MemoryDevice
	mgr *Manager
	udp *net.UDPConn
}

func newSide(t *testing.T, name string) *side {
	t.Helper()
	kp, _ := crypto.GenerateKeyPair()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dev := tun.NewMemoryDevice(name, 1420)
	mgr, err := NewManager(name, WithTunDevice(dev), WithPrivateKey(kp.PrivateKey), WithSharedSocket(udp, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close(); udp.Close(); dev.Close() })
	return &side{kp: kp, dev: dev, mgr: mgr, udp: udp}
}

// TestWireGuardOverRelay runs a real WireGuard handshake and data transfer
// between two devices whose only path is the DERP relay: their peer endpoints
// are relay endpoints, so no UDP datagram ever flows between them.
func TestWireGuardOverRelay(t *testing.T) {
	a, b := newSide(t, "rel-a"), newSide(t, "rel-b")

	relaySrv, _ := crypto.GenerateKeyPair()
	srv, _ := derp.NewServer(relaySrv)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ca, err := derp.ConnectDERP(ctx, l.Addr().String(), a.kp)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	cb, err := derp.ConnectDERP(ctx, l.Addr().String(), b.kp)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	if err := a.mgr.AttachRelay(ca); err != nil {
		t.Fatal(err)
	}
	if err := b.mgr.AttachRelay(cb); err != nil {
		t.Fatal(err)
	}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(a.mgr.ApplyPeer(PeerConfig{PublicKey: b.kp.PublicKey, Endpoint: RelayEndpoint(b.kp.PublicKey), AllowedIPs: []string{"100.64.0.2/32"}}))
	must(b.mgr.ApplyPeer(PeerConfig{PublicKey: a.kp.PublicKey, Endpoint: RelayEndpoint(a.kp.PublicKey), AllowedIPs: []string{"100.64.0.1/32"}}))
	time.Sleep(100 * time.Millisecond) // sessions registered at the relay

	payload := []byte("over-the-relay")
	must(a.dev.InjectPacket(ipv4Packet(t, "100.64.0.1", "100.64.0.2", payload)))

	got := make(chan []byte, 1)
	go func() {
		pkt, _ := b.dev.EjectPacket()
		got <- pkt
	}()
	select {
	case pkt := <-got:
		if !bytes.HasSuffix(pkt, payload) {
			t.Fatalf("payload did not survive the relay: % x", pkt)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no packet arrived through the relay")
	}

	// And back, so both directions of the handshake worked.
	must(b.dev.InjectPacket(ipv4Packet(t, "100.64.0.2", "100.64.0.1", []byte("reply"))))
	back := make(chan []byte, 1)
	go func() {
		pkt, _ := a.dev.EjectPacket()
		back <- pkt
	}()
	select {
	case pkt := <-back:
		if !bytes.HasSuffix(pkt, []byte("reply")) {
			t.Fatalf("bad reply: % x", pkt)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no reply arrived through the relay")
	}
}

// TestNudgeStartsHandshakeAfterRemoteLearnsUs: the initiator's first handshake
// is dropped because the remote does not know it yet; once the remote adds the
// peer, a nudge must complete the handshake without waiting for the 5s retry.
func TestNudgeStartsHandshakeAfterRemoteLearnsUs(t *testing.T) {
	a, b := newSide(t, "nudge-a"), newSide(t, "nudge-b")
	bAddr := b.udp.LocalAddr().(*net.UDPAddr)
	aAddr := a.udp.LocalAddr().(*net.UDPAddr)

	if err := a.mgr.ApplyPeer(PeerConfig{PublicKey: b.kp.PublicKey, Endpoint: bAddr.String(), AllowedIPs: []string{"100.64.0.2/32"}, PersistentKeepalive: 25 * time.Second}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the initiation reaches b, which has no such peer
	if at, _ := a.mgr.LastHandshake(b.kp.PublicKey); !at.IsZero() {
		t.Fatal("no handshake can exist yet")
	}

	if err := b.mgr.ApplyPeer(PeerConfig{PublicKey: a.kp.PublicKey, Endpoint: aAddr.String(), AllowedIPs: []string{"100.64.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.mgr.Nudge(b.kp.PublicKey); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second) // well under WireGuard's 5s retry
	for time.Now().Before(deadline) {
		if at, _ := a.mgr.LastHandshake(b.kp.PublicKey); !at.IsZero() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("nudge did not start a handshake")
}
