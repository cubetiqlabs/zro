package router

import (
	"testing"
)

func TestRouterTable(t *testing.T) {
	tbl := NewTable()

	targetExact := RouteTarget{
		PublicKey:   "pubkey-exact",
		Endpoint:    "192.168.1.100:51820",
		IsDirectP2P: true,
		Metric:      10,
	}

	targetSubnet := RouteTarget{
		PublicKey:   "pubkey-subnet",
		Endpoint:    "10.0.0.1:51820",
		ViaPoPCode:  "SG",
		IsDirectP2P: false,
		Metric:      100,
	}

	// 1. Add subnet route 100.64.0.0/16
	if err := tbl.AddSubnetRoute("100.64.0.0/16", targetSubnet); err != nil {
		t.Fatalf("AddSubnetRoute failed: %v", err)
	}

	// Test invalid CIDR
	if err := tbl.AddSubnetRoute("invalid-cidr", targetSubnet); err == nil {
		t.Fatalf("expected error on invalid CIDR")
	}

	// 2. Lookup IP matching subnet
	resSubnet, found := tbl.Lookup("100.64.1.50")
	if !found || resSubnet.PublicKey != "pubkey-subnet" {
		t.Fatalf("expected lookup to find subnet route, got %v (found: %v)", resSubnet, found)
	}

	// 3. Add specific /32 exact route: 100.64.1.50
	tbl.SetRoute("100.64.1.50", targetExact)

	// Exact route must take precedence over subnet
	resExact, found := tbl.Lookup("100.64.1.50")
	if !found || resExact.PublicKey != "pubkey-exact" || !resExact.IsDirectP2P {
		t.Fatalf("expected exact route to take precedence, got %v", resExact)
	}

	// 4. Test Snapshot
	snap := tbl.Snapshot()
	if len(snap) != 1 || snap["100.64.1.50"].PublicKey != "pubkey-exact" {
		t.Fatalf("expected snapshot with 1 exact route, got %v", snap)
	}

	// 5. Remove route
	tbl.RemoveRoute("100.64.1.50")
	// After removing exact route, subnet route should match again
	resAfterRemove, found := tbl.Lookup("100.64.1.50")
	if !found || resAfterRemove.PublicKey != "pubkey-subnet" {
		t.Fatalf("expected fallback to subnet route after exact route removal, got %v", resAfterRemove)
	}

	// 6. Lookup IP outside subnet
	_, foundOutside := tbl.Lookup("192.168.99.1")
	if foundOutside {
		t.Fatalf("expected not found for IP outside routes")
	}
}
