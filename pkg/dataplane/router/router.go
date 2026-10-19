package router

import (
	"fmt"
	"net"
	"sync"
)

// RouteTarget defines the forwarding target for an overlay IP or subnet.
type RouteTarget struct {
	PublicKey   string `json:"public_key"`
	Endpoint    string `json:"endpoint,omitempty"` // Direct UDP endpoint (e.g. "203.0.113.5:51820")
	ViaPoPCode  string `json:"via_pop_code,omitempty"` // PoP code if relayed (e.g. "KH", "SG")
	IsDirectP2P bool   `json:"is_direct_p2p"`
	Metric      int    `json:"metric"`
}

// Table represents an in-memory high-speed routing table for the overlay network.
type Table struct {
	mu     sync.RWMutex
	routes map[string]RouteTarget // exact /32 or /128 IP match
	subnets []subnetRoute
}

type subnetRoute struct {
	cidr   *net.IPNet
	target RouteTarget
}

// NewTable creates a new in-memory routing table.
func NewTable() *Table {
	return &Table{
		routes: make(map[string]RouteTarget),
	}
}

// SetRoute registers or updates a route for an overlay IP address.
func (t *Table) SetRoute(ipStr string, target RouteTarget) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes[ipStr] = target
}

// AddSubnetRoute registers a CIDR subnet route (e.g. "192.168.1.0/24").
func (t *Table) AddSubnetRoute(cidrStr string, target RouteTarget) error {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Update if exists or append
	for i, r := range t.subnets {
		if r.cidr.String() == ipNet.String() {
			t.subnets[i].target = target
			return nil
		}
	}

	t.subnets = append(t.subnets, subnetRoute{cidr: ipNet, target: target})
	return nil
}

// Lookup finds the best RouteTarget for a destination IP.
func (t *Table) Lookup(dstIP string) (*RouteTarget, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 1. Check exact IP match first (O(1))
	if target, found := t.routes[dstIP]; found {
		return &target, true
	}

	// 2. Check subnet routes
	ip := net.ParseIP(dstIP)
	if ip != nil {
		for _, sr := range t.subnets {
			if sr.cidr.Contains(ip) {
				return &sr.target, true
			}
		}
	}

	return nil, false
}

// RemoveRoute deletes a route for an overlay IP.
func (t *Table) RemoveRoute(ipStr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.routes, ipStr)
}

// Snapshot returns a copy of all current exact routes.
func (t *Table) Snapshot() map[string]RouteTarget {
	t.mu.RLock()
	defer t.mu.RUnlock()

	snap := make(map[string]RouteTarget, len(t.routes))
	for k, v := range t.routes {
		snap[k] = v
	}
	return snap
}
