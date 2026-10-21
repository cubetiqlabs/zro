package agent

import (
	"testing"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/tun"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
)

func TestConnectMovesTheOverlayPrefixToTheNewPoP(t *testing.T) {
	self, _ := crypto.GenerateKeyPair()
	dev := tun.NewMemoryDevice("agent-t0", 1420)
	defer dev.Close()
	wg, err := wireguard.NewManager("agent-t0", wireguard.WithTunDevice(dev), wireguard.WithPrivateKey(self.PrivateKey), wireguard.WithListenPort(0))
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	link := &PoPLink{WG: wg, Interface: "agent-t0"}
	prefixes := core.OverlayPrefixes("", "")
	a, _ := crypto.GenerateKeyPair()
	b, _ := crypto.GenerateKeyPair()

	if err := link.Connect(core.EdgePoP{PoPCode: "KH", PublicKey: a.PublicKey, PublicEndpoint: "127.0.0.1:1"}, prefixes); err != nil {
		t.Fatal(err)
	}
	if err := link.Connect(core.EdgePoP{PoPCode: "SG", PublicKey: b.PublicKey, PublicEndpoint: "127.0.0.1:2"}, prefixes); err != nil {
		t.Fatal(err)
	}

	peers, _ := wg.ListPeers()
	if len(peers) != 1 || peers[0].PublicKey != b.PublicKey {
		t.Fatalf("only the new PoP may hold the overlay prefix, got %+v", peers)
	}
	if err := link.Connect(core.EdgePoP{PoPCode: "X"}, prefixes); err == nil {
		t.Fatal("a PoP without a key must be rejected")
	}
}
