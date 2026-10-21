package edge

import (
	"testing"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
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
