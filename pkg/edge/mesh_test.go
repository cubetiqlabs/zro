package edge

import (
	"encoding/base64"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
)

func node(key, v4, home string, endpoints ...string) core.Node {
	n := core.Node{PublicKey: key, OverlayIPv4: v4, OverlayIPv6: "fd00:cafe::" + v4[len(v4)-1:], Endpoints: endpoints}
	if home != "" {
		n.AssignedPoP = &core.EdgePoP{PoPCode: home}
	}
	return n
}

func byKey(peers []wireguard.PeerConfig) map[string]wireguard.PeerConfig {
	m := map[string]wireguard.PeerConfig{}
	for _, p := range peers {
		m[p.PublicKey] = p
	}
	return m
}

func TestPlanPeersRoutesRemoteNodesViaTheirHomePoP(t *testing.T) {
	st := &meshState{
		PoPs: []core.EdgePoP{
			{PoPCode: "KH", PublicKey: "pop-kh", PublicEndpoint: "1.1.1.1:51820"},
			{PoPCode: "SG", PublicKey: "pop-sg", PublicEndpoint: "2.2.2.2:51820"},
			{PoPCode: "DE", PublicKey: "pop-de", PublicEndpoint: "3.3.3.3:51820"},
		},
		Nodes: []core.Node{
			node("n-local", "100.64.0.2", "KH", "9.9.9.9:4000"),
			node("n-sg", "100.64.0.3", "SG"),
			node("n-de1", "100.64.0.4", "DE"),
			node("n-de2", "100.64.0.5", "DE"),
			node("n-nohome", "100.64.0.6", ""),
		},
	}
	peers := byKey(planPeers("KH", st))

	if _, ok := peers["pop-kh"]; ok {
		t.Fatal("a PoP must not peer with itself")
	}
	// Locally homed and unhomed nodes are direct peers with their own addresses.
	if p := peers["n-local"]; p.Endpoint != "9.9.9.9:4000" || len(p.AllowedIPs) != 2 || p.AllowedIPs[0] != "100.64.0.2/32" {
		t.Fatalf("unexpected local node peer %+v", p)
	}
	if _, ok := peers["n-nohome"]; !ok {
		t.Fatal("a node without a home PoP should be a direct peer")
	}
	// Remote nodes are not peers; their addresses ride on the home PoP's peer.
	for _, k := range []string{"n-sg", "n-de1", "n-de2"} {
		if _, ok := peers[k]; ok {
			t.Fatalf("remote node %s must not be a direct peer", k)
		}
	}
	if got := peers["pop-sg"].AllowedIPs; len(got) != 2 || got[0] != "100.64.0.3/32" {
		t.Fatalf("SG should carry only its node, got %v", got)
	}
	if got := peers["pop-de"].AllowedIPs; len(got) != 4 {
		t.Fatalf("DE should carry both of its nodes (v4+v6), got %v", got)
	}

	// Handshake initiation: the PoP never initiates toward nodes, and on the
	// backbone only the lower PoP code does (DE < KH < SG).
	if peers["n-local"].PersistentKeepalive != 0 {
		t.Fatal("a PoP must not start handshakes toward nodes")
	}
	if peers["pop-sg"].PersistentKeepalive == 0 {
		t.Fatal("KH < SG, so KH must initiate toward SG")
	}
	if peers["pop-de"].PersistentKeepalive != 0 {
		t.Fatal("DE < KH, so DE initiates and KH must not")
	}
	if got := byKey(planPeers("SG", st))["pop-kh"].PersistentKeepalive; got != 0 {
		t.Fatalf("SG must not initiate toward KH (both ends would collide), got %v", got)
	}

	// No AllowedIP may belong to two peers, or WireGuard would silently move it.
	seen := map[string]string{}
	for _, p := range peers {
		for _, ip := range p.AllowedIPs {
			if owner, dup := seen[ip]; dup {
				t.Fatalf("%s claimed by both %s and %s", ip, owner, p.PublicKey)
			}
			seen[ip] = p.PublicKey
		}
	}
}

func TestRelayAuthorizationFailsClosedAndKnowsTheMesh(t *testing.T) {
	e := &PoPDaemon{}
	var anyKey [32]byte
	if e.isKnownKey(anyKey) {
		t.Fatal("before the first sync nobody may use the relay")
	}

	nodeKey := make([]byte, 32)
	nodeKey[0] = 7
	st := &meshState{Nodes: []core.Node{{PublicKey: base64.StdEncoding.EncodeToString(nodeKey)}}, PoPs: []core.EdgePoP{{PublicKey: "not-base64!"}}}
	e.knownKeys.Store(knownKeySet(st))

	var known [32]byte
	copy(known[:], nodeKey)
	if !e.isKnownKey(known) {
		t.Fatal("a mesh node must be allowed")
	}
	if e.isKnownKey([32]byte{1}) {
		t.Fatal("an unknown key must be refused")
	}
}

func TestPlanPeersRoutesPoPAddressThroughThatPoP(t *testing.T) {
	st := &meshState{PoPs: []core.EdgePoP{
		{PoPCode: "KH", PublicKey: "a", OverlayIPv4: "100.64.255.254", OverlayIPv6: "fd00::fe"},
		{PoPCode: "SG", PublicKey: "b", OverlayIPv4: "100.64.255.253"},
	}}
	for _, p := range planPeers("KH", st) {
		if p.PublicKey == "b" && (len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "100.64.255.253/32") {
			t.Fatalf("allowed ips = %v", p.AllowedIPs)
		}
		if p.PublicKey == "a" {
			t.Fatal("self must not be a peer")
		}
	}
}
