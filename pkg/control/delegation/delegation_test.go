package delegation

import (
	"context"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
)

func TestDelegationEngine(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	engine := NewEngine(db.EdgePoPs)

	nodeID := uuid.New()

	// 1. Delegate with no healthy PoPs -> ErrNoHealthyPoP
	_, err = engine.Delegate(ctx, nodeID)
	if err != ErrNoHealthyPoP {
		t.Fatalf("expected ErrNoHealthyPoP, got %v", err)
	}

	// 2. Seed 3 PoPs: KH (Cambodia), SG (Singapore), US (Ashburn)
	popKH := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "KH",
		Region:         "Cambodia",
		PublicEndpoint: "173.1.1.1:51820",
		Weight:         100,
		IsHealthy:      true,
		LastSeenAt:     time.Now(),
	}
	popSG := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "SG",
		Region:         "Singapore",
		PublicEndpoint: "123.1.1.1:51820",
		Weight:         100,
		IsHealthy:      true,
		LastSeenAt:     time.Now(),
	}
	popUS := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "US",
		Region:         "United States",
		PublicEndpoint: "145.1.1.1:51820",
		Weight:         100,
		IsHealthy:      true,
		LastSeenAt:     time.Now(),
	}

	_ = db.EdgePoPs.Create(ctx, popKH)
	_ = db.EdgePoPs.Create(ctx, popSG)
	_ = db.EdgePoPs.Create(ctx, popUS)

	// Record latency probes: KH=5ms, SG=30ms, US=200ms
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "KH",
		RTT:        5 * time.Millisecond,
		PacketLoss: 0.0,
		Timestamp:  time.Now(),
	})
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "SG",
		RTT:        30 * time.Millisecond,
		PacketLoss: 0.0,
		Timestamp:  time.Now(),
	})
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "US",
		RTT:        200 * time.Millisecond,
		PacketLoss: 0.0,
		Timestamp:  time.Now(),
	})

	res, err := engine.Delegate(ctx, nodeID)
	if err != nil {
		t.Fatalf("Delegate failed: %v", err)
	}

	if res.PrimaryPoP.PoPCode != "KH" {
		t.Fatalf("expected PrimaryPoP KH (5ms), got %s", res.PrimaryPoP.PoPCode)
	}
	if res.SecondaryPoP == nil || res.SecondaryPoP.PoPCode != "SG" {
		t.Fatalf("expected SecondaryPoP SG (30ms), got %v", res.SecondaryPoP)
	}

	// 3. Packet loss penalty test: If KH suffers 50% packet loss, SG should win
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "KH",
		RTT:        5 * time.Millisecond,
		PacketLoss: 0.5, // +500ms penalty
		Timestamp:  time.Now(),
	})

	resLoss, err := engine.Delegate(ctx, nodeID)
	if err != nil {
		t.Fatalf("Delegate with loss failed: %v", err)
	}
	if resLoss.PrimaryPoP.PoPCode != "SG" {
		t.Fatalf("expected PrimaryPoP SG to win over degraded KH, got %s", resLoss.PrimaryPoP.PoPCode)
	}

	// 4. Test expired probe penalty: Probe older than 10 minutes falls back to 500ms
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "SG",
		RTT:        1 * time.Millisecond,
		PacketLoss: 0.0,
		Timestamp:  time.Now().Add(-15 * time.Minute), // expired
	})
	// KH fresh probe with zero loss
	engine.RecordProbe(core.LatencySample{
		NodeID:     nodeID,
		PoPCode:    "KH",
		RTT:        10 * time.Millisecond,
		PacketLoss: 0.0,
		Timestamp:  time.Now(),
	})

	resExpired, err := engine.Delegate(ctx, nodeID)
	if err != nil {
		t.Fatalf("Delegate with expired probe failed: %v", err)
	}
	if resExpired.PrimaryPoP.PoPCode != "KH" {
		t.Fatalf("expected PrimaryPoP KH to win over expired SG, got %s", resExpired.PrimaryPoP.PoPCode)
	}
}

func TestPruneAndForgetBoundProbeHistory(t *testing.T) {
	e := NewEngine(nil)
	fresh, stale, gone := uuid.New(), uuid.New(), uuid.New()
	e.RecordProbe(core.LatencySample{NodeID: fresh, PoPCode: "KH", Timestamp: time.Now()})
	e.RecordProbe(core.LatencySample{NodeID: stale, PoPCode: "KH", Timestamp: time.Now().Add(-time.Hour)})
	e.RecordProbe(core.LatencySample{NodeID: gone, PoPCode: "KH", Timestamp: time.Now()})

	e.Prune(10 * time.Minute)
	e.Forget(gone)

	if len(e.recentProbes) != 1 || e.recentProbes[fresh] == nil {
		t.Fatalf("expected only the fresh node to remain, got %d entries", len(e.recentProbes))
	}
}
