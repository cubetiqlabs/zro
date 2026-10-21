package ipam

import (
	"testing"
)

func TestIPAMAllocations(t *testing.T) {
	existing := []string{"100.64.0.2", "100.64.0.3"}
	mgr, err := NewIPAM("100.64.0.0/24", existing)
	if err != nil {
		t.Fatalf("failed to create IPAM: %v", err)
	}

	// First free should be 100.64.0.4 because .0 (net), .1 (gw), .2, .3 are taken
	ip1, err := mgr.AllocateNext()
	if err != nil {
		t.Fatalf("AllocateNext failed: %v", err)
	}
	if ip1 != "100.64.0.4" {
		t.Fatalf("expected 100.64.0.4, got %s", ip1)
	}

	ip2, err := mgr.AllocateNext()
	if err != nil {
		t.Fatalf("AllocateNext failed: %v", err)
	}
	if ip2 != "100.64.0.5" {
		t.Fatalf("expected 100.64.0.5, got %s", ip2)
	}

	// Release 100.64.0.2 and allocate
	mgr.Release("100.64.0.2")
	ipReclaimed, err := mgr.AllocateNext()
	if err != nil {
		t.Fatalf("re-allocation failed: %v", err)
	}
	if ipReclaimed != "100.64.0.2" {
		t.Fatalf("expected 100.64.0.2 after release, got %s", ipReclaimed)
	}

	// Test IPv6 derivation
	v6, err := DeriveIPv6("fd00:cafe:1::/64", "100.64.0.10")
	if err != nil {
		t.Fatalf("DeriveIPv6 failed: %v", err)
	}
	if v6 == "" {
		t.Fatalf("expected non-empty derived IPv6")
	}
}
