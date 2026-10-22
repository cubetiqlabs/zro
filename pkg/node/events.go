package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
	"github.com/cubetiqlabs/zro/pkg/realtime"
)

const (
	p2pKeepalive            = 20 * time.Second
	responderKeepaliveDelay = 3 * time.Second
)

// maxConcurrentConnects bounds the hole punches started by one peer refresh.
const maxConcurrentConnects = 8

// realtimeListener keeps the node's view of the mesh current: membership
// changes refresh the peer set, and punch requests are answered immediately.
func (d *Daemon) realtimeListener(ctx context.Context) {
	defer d.wg.Done()
	realtime.Run(ctx, realtime.Config{
		Endpoint:   d.cfg.PlaneEndpoint,
		GRPC:       d.grpcClient,
		Role:       "node",
		ID:         d.cfg.Hostname,
		Credential: d.token.Get,
		Events:     []string{"node_joined", "node_left", "acl_rules_updated", "p2p_punch_requested"},
		Raw: func(name string, data json.RawMessage) {
			if name == "p2p_punch_requested" {
				go d.answerPunchRequest(ctx, data)
			}
		},
	}, func(ctx context.Context, evs []string) {
		for _, e := range evs {
			switch e {
			case "node_joined", "node_left":
				d.syncPeers(ctx)
			case "acl_rules_updated":
				d.syncPolicy(ctx)
			}
		}
	})
}

// fetchPeers returns the current members of the node's network.
func (d *Daemon) fetchPeers(ctx context.Context) ([]core.Node, error) {
	if d.grpcClient != nil {
		g, err := d.grpcClient.ListPeers(ctx)
		if err != nil {
			return nil, err
		}
		peers := make([]core.Node, 0, len(g.Peers))
		for _, p := range g.Peers {
			peers = append(peers, core.Node{
				Hostname: p.Hostname, PublicKey: p.PublicKey,
				OverlayIPv4: p.OverlayIpv4, OverlayIPv6: p.OverlayIpv6,
				Endpoints: core.StringList(p.Endpoints), Tags: core.StringList(p.Tags),
			})
		}
		return peers, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.PlaneEndpoint+"/api/v1/network/"+d.networkID+"/peers", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer list rejected: status %d", resp.StatusCode)
	}
	var peers []core.Node
	return peers, json.NewDecoder(resp.Body).Decode(&peers)
}

// syncPeers reconciles the node's peers with the plane: new members are
// connected (P2P first), departed ones are dropped.
func (d *Daemon) syncPeers(ctx context.Context) {
	peers, err := d.fetchPeers(ctx)
	if err != nil {
		slog.Debug("Peer refresh failed", "error", err)
		return
	}

	current := make(map[string]core.Node, len(peers))
	for _, p := range peers {
		if p.PublicKey != "" && p.PublicKey != d.keyPair.PublicKey {
			current[p.PublicKey] = p
		}
	}

	d.peersMu.RLock()
	var gone []core.Node
	var fresh []core.Node
	for key, p := range d.peers {
		if _, ok := current[key]; !ok {
			gone = append(gone, p)
		}
	}
	for key, p := range current {
		if _, ok := d.peers[key]; !ok {
			fresh = append(fresh, p)
		}
	}
	d.peersMu.RUnlock()

	for _, p := range gone {
		d.dropPeer(p)
	}

	sem := make(chan struct{}, maxConcurrentConnects)
	var wg sync.WaitGroup
	for _, p := range fresh {
		wg.Add(1)
		sem <- struct{}{}
		go func(p core.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			d.connectPeer(ctx, p)
		}(p)
	}
	wg.Wait()
}

// dropPeer forgets a peer that left the mesh.
func (d *Daemon) dropPeer(p core.Node) {
	d.peersMu.Lock()
	delete(d.peers, p.PublicKey)
	d.peersMu.Unlock()
	_ = d.wgManager.RemovePeer(p.PublicKey)
	slog.Info("Peer left the mesh", "peer", p.Hostname, "overlay_ipv4", p.OverlayIPv4)
}

// answerPunchRequest is the responder half of hole punching: when another node
// asks to reach this one, punch back at it simultaneously so both NATs open.
func (d *Daemon) answerPunchRequest(ctx context.Context, data json.RawMessage) {
	if !d.cfg.EnableP2P {
		return
	}
	var req struct {
		TargetNodeID       string   `json:"target_node_id"`
		InitiatorPubKey    string   `json:"initiator_pubkey"`
		InitiatorEndpoints []string `json:"initiator_endpoints"`
		InitiatorOverlay   string   `json:"initiator_overlay"`
	}
	if err := json.Unmarshal(data, &req); err != nil || req.TargetNodeID != d.nodeID.String() || req.InitiatorOverlay == "" {
		return
	}

	for _, ep := range req.InitiatorEndpoints {
		if ok, rtt := d.punchTo(ctx, ep, 2*time.Second); ok {
			peer := wireguard.PeerConfig{
				PublicKey:  req.InitiatorPubKey,
				Endpoint:   ep,
				AllowedIPs: []string{req.InitiatorOverlay + "/32"},
			}
			// The initiator starts the handshake. If both sides began with a
			// keepalive, both would initiate at once and their handshakes would
			// keep colliding, so ours is enabled once the handshake has settled.
			if err := d.wgManager.ApplyPeer(peer); err != nil {
				return
			}
			slog.Info("Direct P2P path opened at the request of a peer", "endpoint", ep, "rtt", rtt)
			time.AfterFunc(responderKeepaliveDelay, func() {
				peer.PersistentKeepalive = p2pKeepalive
				_ = d.wgManager.ApplyPeer(peer)
			})
			return
		}
	}
}
