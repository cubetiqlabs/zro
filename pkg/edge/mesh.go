package edge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/dataplane/netcfg"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
)

// popKeepalive keeps a PoP-to-PoP backbone link up. Only one end may start with
// a keepalive: if both did they would initiate handshakes at the same instant
// and keep colliding. Nodes initiate toward the PoP themselves (their keepalive
// also holds their NAT mapping open), so the PoP sets none toward nodes.
const popKeepalive = 20 * time.Second

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
			// A PoP's own address is reached through that PoP.
			cfg := &wireguard.PeerConfig{PublicKey: p.PublicKey, Endpoint: p.PublicEndpoint, AllowedIPs: overlayCIDRs(p.OverlayIPv4, p.OverlayIPv6)}
			if self < p.PoPCode { // the lower code initiates
				cfg.PersistentKeepalive = popKeepalive
			}
			pops[p.PoPCode] = cfg
		}
	}

	var peers []wireguard.PeerConfig
	for _, n := range st.Nodes {
		if n.PublicKey == "" || n.OverlayIPv4 == "" {
			continue
		}
		ips := overlayCIDRs(n.OverlayIPv4, n.OverlayIPv6)

		if home := homeOf(n); home != "" && home != self && pops[home] != nil {
			pops[home].AllowedIPs = append(pops[home].AllowedIPs, ips...)
			continue
		}
		var endpoint string
		if len(n.Endpoints) > 0 {
			endpoint = n.Endpoints[0]
		}
		peers = append(peers, wireguard.PeerConfig{
			PublicKey:  n.PublicKey,
			Endpoint:   endpoint,
			AllowedIPs: ips,
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

// overlayCIDRs turns host addresses into the /32 and /128 prefixes WireGuard
// routes; empty addresses are skipped.
func overlayCIDRs(v4, v6 string) []string {
	var out []string
	if v4 != "" {
		out = append(out, v4+"/32")
	}
	if v6 != "" {
		out = append(out, v6+"/128")
	}
	return out
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
			st.PoPs = append(st.PoPs, core.EdgePoP{PoPCode: p.PopCode, Region: p.Region, PublicEndpoint: p.PublicEndpoint, PublicKey: p.PublicKey, OverlayIPv4: p.OverlayIpv4, OverlayIPv6: p.OverlayIpv6})
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
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	st, err := e.fetchMesh(ctx)
	if err != nil {
		if now := time.Now().UnixNano(); now-e.lastSyncWarn.Load() > int64(time.Minute) {
			e.lastSyncWarn.Store(now)
			slog.Warn("Edge mesh sync failed (will keep retrying)", "pop_code", e.cfg.PoPCode, "error", err)
		}
		return
	}

	e.peersMu.Lock()
	changed := !e.synced || e.peerCount != len(st.Nodes)
	e.synced = true
	e.peerCount = len(st.Nodes)
	e.peersMu.Unlock()
	if changed {
		slog.Info("Edge mesh synchronized", "pop_code", e.cfg.PoPCode, "nodes", len(st.Nodes), "pops", len(st.PoPs))
	}
	e.knownKeys.Store(knownKeySet(st))

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

// knownKeySet collects the public keys of every node and PoP in the mesh.
func knownKeySet(st *meshState) *map[[32]byte]struct{} {
	keys := make(map[[32]byte]struct{}, len(st.Nodes)+len(st.PoPs))
	add := func(b64 string) {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) == 32 {
			var k [32]byte
			copy(k[:], raw)
			keys[k] = struct{}{}
		}
	}
	for _, n := range st.Nodes {
		add(n.PublicKey)
	}
	for _, p := range st.PoPs {
		add(p.PublicKey)
	}
	return &keys
}

// isKnownKey authorizes a relay client. Until the first sync nobody is known,
// so the relay fails closed rather than open.
func (e *PoPDaemon) isKnownKey(pub [32]byte) bool {
	keys := e.knownKeys.Load()
	if keys == nil {
		return false
	}
	_, ok := (*keys)[pub]
	return ok
}
