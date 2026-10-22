package wireguard

import (
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/dataplane/tun"
)

func TestWireGuardManagerUserspace(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair failed: %v", err)
	}

	memDev := tun.NewMemoryDevice("wg-test0", 1420)
	defer memDev.Close()

	mgr, err := NewManager("wg-test0",
		WithTunDevice(memDev),
		WithPrivateKey(kp.PrivateKey),
		WithListenPort(0), // dynamic UDP port
	)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	if !mgr.IsUserspace() {
		t.Fatalf("expected mgr.IsUserspace() == true")
	}

	peerKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate peer keypair: %v", err)
	}

	peerCfg := PeerConfig{
		PublicKey:           peerKP.PublicKey,
		Endpoint:            "127.0.0.1:51820",
		AllowedIPs:          []string{"100.64.0.2/32"},
		PersistentKeepalive: 25 * time.Second,
	}

	// 1. Test ApplyPeer
	if err := mgr.ApplyPeer(peerCfg); err != nil {
		t.Fatalf("ApplyPeer failed: %v", err)
	}

	peers, err := mgr.ListPeers()
	if err != nil || len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d (err: %v)", len(peers), err)
	}
	if peers[0].PublicKey != peerKP.PublicKey {
		t.Fatalf("expected peer key %s, got %s", peerKP.PublicKey, peers[0].PublicKey)
	}

	// 2. Test SetPrivateKey
	newKP, _ := crypto.GenerateKeyPair()
	if err := mgr.SetPrivateKey(newKP.PrivateKey); err != nil {
		t.Fatalf("SetPrivateKey failed: %v", err)
	}

	// 3. Test RemovePeer
	if err := mgr.RemovePeer(peerKP.PublicKey); err != nil {
		t.Fatalf("RemovePeer failed: %v", err)
	}

	peersAfterRemove, err := mgr.ListPeers()
	if err != nil || len(peersAfterRemove) != 0 {
		t.Fatalf("expected 0 peers after removal, got %d", len(peersAfterRemove))
	}
}

func TestWireGuardManagerFallback(t *testing.T) {
	// Without TUN device and in unprivileged non-kernel environment, should not panic
	mgr, err := NewManager("wg-fallback0", WithKernel(false))
	if err != nil {
		t.Fatalf("NewManager returned unexpected error: %v", err)
	}
	defer mgr.Close()

	if !mgr.IsSimulated() {
		t.Fatalf("expected IsSimulated() == true when kernel is disabled and no tun device")
	}

	peerKP, _ := crypto.GenerateKeyPair()
	cfg := PeerConfig{
		PublicKey:  peerKP.PublicKey,
		AllowedIPs: []string{"100.64.0.5/32"},
	}

	if err := mgr.ApplyPeer(cfg); err != nil {
		t.Fatalf("ApplyPeer in simulated mode failed: %v", err)
	}

	peers, _ := mgr.ListPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	_ = mgr.RemovePeer(peerKP.PublicKey)
	peers, _ = mgr.ListPeers()
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestReconcileAppliesChangesAndRemovesStalePeers(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	dev := tun.NewMemoryDevice("wg-rec0", 1420)
	defer dev.Close()
	mgr, err := NewManager("wg-rec0", WithTunDevice(dev), WithPrivateKey(kp.PrivateKey), WithListenPort(0))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	a, _ := crypto.GenerateKeyPair()
	b, _ := crypto.GenerateKeyPair()
	peerA := PeerConfig{PublicKey: a.PublicKey, Endpoint: "127.0.0.1:1111", AllowedIPs: []string{"100.64.0.2/32"}}
	peerB := PeerConfig{PublicKey: b.PublicKey, AllowedIPs: []string{"100.64.0.3/32"}}

	if err := mgr.Reconcile([]PeerConfig{peerA, peerB}); err != nil {
		t.Fatal(err)
	}
	if peers, _ := mgr.ListPeers(); len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}

	// B left the mesh: it must be removed, A (unchanged) must be left alone.
	if err := mgr.Reconcile([]PeerConfig{peerA}); err != nil {
		t.Fatal(err)
	}
	peers, _ := mgr.ListPeers()
	if len(peers) != 1 || peers[0].PublicKey != a.PublicKey {
		t.Fatalf("expected only peer A to remain, got %+v", peers)
	}
}

func TestSamePeerIgnoresAllowedIPOrder(t *testing.T) {
	a := PeerConfig{PublicKey: "k", AllowedIPs: []string{"1.1.1.1/32", "2.2.2.2/32"}}
	b := PeerConfig{PublicKey: "k", AllowedIPs: []string{"2.2.2.2/32", "1.1.1.1/32"}}
	if !samePeer(a, b) {
		t.Fatal("order of allowed IPs must not count as a change")
	}
	b.AllowedIPs = []string{"2.2.2.2/32", "3.3.3.3/32"}
	if samePeer(a, b) {
		t.Fatal("different allowed IPs must count as a change")
	}
}
