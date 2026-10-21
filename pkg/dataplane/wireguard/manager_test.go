package wireguard

import (
	"testing"
	"time"

	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/tun"
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
