package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
)

func TestSyncPeersAddsNewMembersAndDropsDepartedOnes(t *testing.T) {
	a, _ := crypto.GenerateKeyPair()
	b, _ := crypto.GenerateKeyPair()
	members := atomic.Pointer[[]core.Node]{}
	set := func(nodes ...core.Node) { members.Store(&nodes) }
	set(core.Node{PublicKey: a.PublicKey, Hostname: "a", OverlayIPv4: "100.64.0.2"})

	plane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(*members.Load())
	}))
	defer plane.Close()

	d, err := NewDaemon(&config.NodeConfig{Hostname: "me", InterfaceName: "zro-ev1", MTU: 1420, PlaneEndpoint: plane.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	d.networkID = "net1"
	d.cfg.EnableP2P = false // no hole punching in this test: peers fall back to the PoP route

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Our own entry in the list is ignored; a new member is tracked.
	set(core.Node{PublicKey: d.keyPair.PublicKey, Hostname: "me"}, core.Node{PublicKey: a.PublicKey, Hostname: "a", OverlayIPv4: "100.64.0.2"})
	d.syncPeers(ctx)
	if _, ok := d.peers[a.PublicKey]; !ok || len(d.peers) != 1 {
		t.Fatalf("expected exactly peer a, got %v", d.peers)
	}

	// A second member joins, then the first leaves.
	set(core.Node{PublicKey: a.PublicKey, OverlayIPv4: "100.64.0.2"}, core.Node{PublicKey: b.PublicKey, Hostname: "b", OverlayIPv4: "100.64.0.3"})
	d.syncPeers(ctx)
	if len(d.peers) != 2 {
		t.Fatalf("expected 2 peers after a join, got %d", len(d.peers))
	}
	set(core.Node{PublicKey: b.PublicKey, Hostname: "b", OverlayIPv4: "100.64.0.3"})
	d.syncPeers(ctx)
	if _, ok := d.peers[a.PublicKey]; ok || len(d.peers) != 1 {
		t.Fatalf("expected only peer b after a left, got %v", d.peers)
	}
}
