package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/dataplane/netcfg"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
)

const (
	nodeKeepalive = 25 * time.Second
	popKeepalive  = 20 * time.Second
)

// meshState is the plane's view of the mesh as synchronized to this edge.
type meshState struct {
	PoPs     []core.EdgePoP `json:"pops"`
	Nodes    []core.Node    `json:"nodes"`
	Prefixes []string       `json:"prefixes"`
}

// planPeers computes the WireGuard peers of PoP self:
//   - every node homed here (or with no known home) is a direct peer owning its
//     own /32 and /128;
//   - a node homed at another PoP is reached through that PoP, whose peer entry
//     carries the node's addresses as AllowedIPs.
//
// WireGuard assigns an address to exactly one peer, so PoPs never claim the
// whole overlay prefix (two backbone peers doing so would steal it from each
// other).
func planPeers(self string, st *meshState) []wireguard.PeerConfig {
	pops := make(map[string]*wireguard.PeerConfig)
	for _, p := range st.PoPs {
		if p.PoPCode != self && p.PublicKey != "" {
			pops[p.PoPCode] = &wireguard.PeerConfig{
				PublicKey:           p.PublicKey,
				Endpoint:            p.PublicEndpoint,
				PersistentKeepalive: popKeepalive,
			}
		}
	}

	var peers []wireguard.PeerConfig
	for _, n := range st.Nodes {
		if n.PublicKey == "" || n.OverlayIPv4 == "" {
			continue
		}
		ips := []string{n.OverlayIPv4 + "/32"}
		if n.OverlayIPv6 != "" {
			ips = append(ips, n.OverlayIPv6+"/128")
		}

		if home := homeOf(n); home != "" && home != self && pops[home] != nil {
			pops[home].AllowedIPs = append(pops[home].AllowedIPs, ips...)
			continue
		}
		var endpoint string
		if len(n.Endpoints) > 0 {
			endpoint = n.Endpoints[0]
		}
		peers = append(peers, wireguard.PeerConfig{
			PublicKey:           n.PublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          ips,
			PersistentKeepalive: nodeKeepalive,
		})
	}

	codes := make([]string, 0, len(pops))
	for code := range pops {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		peers = append(peers, *pops[code])
	}
	return peers
}

func homeOf(n core.Node) string {
	if n.AssignedPoP != nil {
		return n.AssignedPoP.PoPCode
	}
	return ""
}

// fetchMesh retrieves the mesh over gRPC when configured, otherwise REST.
func (e *PoPDaemon) fetchMesh(ctx context.Context) (*meshState, error) {
	if e.grpcClient != nil {
		g, err := e.grpcClient.SyncEdgeMesh(ctx, &v1.EdgeSyncRequest{PopCode: e.cfg.PoPCode})
		if err != nil {
			return nil, err
		}
		st := &meshState{Prefixes: g.Prefixes}
		for _, p := range g.Pops {
			st.PoPs = append(st.PoPs, core.EdgePoP{PoPCode: p.PopCode, Region: p.Region, PublicEndpoint: p.PublicEndpoint, PublicKey: p.PublicKey})
		}
		for _, n := range g.Nodes {
			node := core.Node{
				Hostname:    n.Hostname,
				PublicKey:   n.PublicKey,
				OverlayIPv4: n.OverlayIpv4,
				OverlayIPv6: n.OverlayIpv6,
				Endpoints:   core.StringList(n.Endpoints),
			}
			if n.AssignedPopCode != "" {
				node.AssignedPoP = &core.EdgePoP{PoPCode: n.AssignedPopCode}
			}
			st.Nodes = append(st.Nodes, node)
		}
		return st, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.PlaneEndpoint+"/api/v1/edge/sync", nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("edge sync rejected: status %d", resp.StatusCode)
	}
	var st meshState
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// syncMeshTopology pulls the mesh and programs WireGuard peers and routes.
func (e *PoPDaemon) syncMeshTopology(ctx context.Context) {
	st, err := e.fetchMesh(ctx)
	if err != nil {
		slog.Debug("Edge mesh sync failed", "pop_code", e.cfg.PoPCode, "error", err)
		return
	}

	e.peersMu.Lock()
	e.peerCount = len(st.Nodes)
	e.peersMu.Unlock()

	if err := e.wgManager.Reconcile(planPeers(e.cfg.PoPCode, st)); err != nil {
		slog.Warn("Edge peer reconcile reported an error", "error", err)
	}

	// Overlay prefixes come from the networks themselves; route each once.
	for _, cidr := range st.Prefixes {
		if e.routed[cidr] {
			continue
		}
		if err := netcfg.AddSubnetRoute(e.cfg.InterfaceName, cidr); err != nil {
			slog.Warn("Could not add edge overlay route", "cidr", cidr, "error", err)
			continue
		}
		e.routed[cidr] = true
	}
}
