package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	controlauth "github.com/cubis/zro/pkg/control/auth"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
)

const testSecret = "service-test-secret"

type fixture struct {
	db      *store.DB
	cfg     *config.ControlPlaneConfig
	network *core.Network
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.NewDB("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1) // serialize statements; the unique indexes still arbitrate
	}
	cfg := &config.ControlPlaneConfig{SecretKey: testSecret}
	network := &core.Network{
		ID: core.GenerateNetworkID(), Name: "n", IPv4CIDR: "100.64.0.0/24", IPv6CIDR: "fd00:cafe::/64",
		DNSDomain: "zro.internal", MTU: 1420, IsActive: true,
	}
	if err := db.Networks.Create(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	return &fixture{db: db, cfg: cfg, network: network}
}

func (f *fixture) service() *Service { return New(f.cfg, f.db, events.NewBus()) }

func (f *fixture) enrollReq(t *testing.T, host string) (EnrollRequest, *crypto.KeyPair) {
	t.Helper()
	kp, _ := crypto.GenerateKeyPair()
	return EnrollRequest{
		Token:     crypto.GenerateEnrollmentToken(testSecret, f.network.ID, host, time.Hour, kp.PublicKey),
		PublicKey: kp.PublicKey,
		Hostname:  host,
	}, kp
}

func TestEnrollIsIdempotentPerKey(t *testing.T) {
	f := newFixture(t)
	svc := f.service()
	ctx := context.Background()
	req, _ := f.enrollReq(t, "node-a")

	first, err := svc.Enroll(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	// Knowing the public key and the (long-lived) enrollment token is not enough
	// to take over a node that is already a member.
	if _, err := svc.Enroll(ctx, req); KindOf(err) != KindConflict {
		t.Fatalf("re-enrolling without the node token must conflict, got %v", err)
	}
	stolen := req
	stolen.CurrentToken = "zro_node_not-the-token"
	if _, err := svc.Enroll(ctx, stolen); KindOf(err) != KindConflict {
		t.Fatalf("re-enrolling with a wrong token must conflict, got %v", err)
	}

	req.CurrentToken = first.NodeToken // a restart: same key, same enrollment token, saved node token
	second, err := svc.Enroll(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	if first.NodeID != second.NodeID || first.OverlayIPv4 != second.OverlayIPv4 {
		t.Fatalf("identity changed across re-enroll: %s/%s vs %s/%s", first.NodeID, first.OverlayIPv4, second.NodeID, second.OverlayIPv4)
	}
	if first.NodeToken == second.NodeToken {
		t.Fatal("re-enroll must rotate the bearer token")
	}
	if n, _ := f.db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(first.NodeToken)); n != nil {
		t.Fatal("the previous token must stop working after re-enroll")
	}
	if nodes, _ := f.db.Nodes.ListByNetworkID(ctx, f.network.ID); len(nodes) != 1 {
		t.Fatalf("expected a single node row, got %d", len(nodes))
	}
}

func TestReplicasNeverHandOutTheSameAddress(t *testing.T) {
	f := newFixture(t)
	replicas := []*Service{f.service(), f.service(), f.service()} // separate in-memory allocators, one DB
	ctx := context.Background()

	const n = 30
	var wg sync.WaitGroup
	ips := make(chan string, n)
	for i := 0; i < n; i++ {
		req, _ := f.enrollReq(t, fmt.Sprintf("node-%d", i))
		wg.Add(1)
		go func(svc *Service) {
			defer wg.Done()
			resp, err := svc.Enroll(ctx, req)
			if err != nil {
				t.Errorf("enroll: %v", err)
				return
			}
			ips <- resp.OverlayIPv4
		}(replicas[i%len(replicas)])
	}
	wg.Wait()
	close(ips)

	seen := map[string]bool{}
	for ip := range ips {
		if seen[ip] {
			t.Fatalf("address %s handed out twice", ip)
		}
		seen[ip] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique addresses, got %d", n, len(seen))
	}
}

func TestDeregisterFreesAddressAndReaperRemovesStaleNodes(t *testing.T) {
	f := newFixture(t)
	svc := f.service()
	ctx := context.Background()

	reqA, _ := f.enrollReq(t, "a")
	a, err := svc.Enroll(ctx, reqA)
	if err != nil {
		t.Fatal(err)
	}
	nodeA, _ := f.db.Nodes.GetByID(ctx, a.NodeID)
	if err := svc.Deregister(ctx, nodeA); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.db.Nodes.GetByID(ctx, a.NodeID); n != nil {
		t.Fatal("node row must be gone after deregister")
	}

	reqB, _ := f.enrollReq(t, "b")
	b, err := svc.Enroll(ctx, reqB)
	if err != nil {
		t.Fatal(err)
	}
	if b.OverlayIPv4 != a.OverlayIPv4 {
		t.Fatalf("freed address %s should be reused, got %s", a.OverlayIPv4, b.OverlayIPv4)
	}

	// Reaper: a node unseen for longer than the TTL is removed, a fresh one stays.
	reqC, _ := f.enrollReq(t, "c")
	c, _ := svc.Enroll(ctx, reqC)
	stale, _ := f.db.Nodes.GetByID(ctx, c.NodeID)
	stale.LastSeenAt = time.Now().Add(-48 * time.Hour)
	_ = f.db.Nodes.Update(ctx, stale)

	if reaped := svc.maintainOnce(ctx, 24*time.Hour); reaped != 1 {
		t.Fatalf("expected 1 reaped node, got %d", reaped)
	}
	if n, _ := f.db.Nodes.GetByID(ctx, c.NodeID); n != nil {
		t.Fatal("stale node should have been reaped")
	}
	if n, _ := f.db.Nodes.GetByID(ctx, b.NodeID); n == nil {
		t.Fatal("fresh node must survive the reaper")
	}
}

func TestProbeLossRehomesNodeToHealthyPoP(t *testing.T) {
	f := newFixture(t)
	svc := f.service()
	ctx := context.Background()
	for _, code := range []string{"a", "b"} {
		pop := &core.EdgePoP{ID: uuid.New(), Region: "r", PublicKey: code, PoPCode: code, PublicEndpoint: code + ":1", IsHealthy: true, Weight: 100, LastSeenAt: time.Now()}
		if err := f.db.EdgePoPs.Create(ctx, pop); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := f.enrollReq(t, "n")
	req.Probes = []core.LatencySample{{PoPCode: "a", RTT: 10 * time.Millisecond}}
	resp, err := svc.Enroll(ctx, req)
	if err != nil || resp.PrimaryPoP.PoPCode != "a" {
		t.Fatalf("expected home a, got %v / %v", resp, err)
	}
	node, _ := f.db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(resp.NodeToken))

	// A healthy home is never displaced by a report.
	svc.ReportProbe(ctx, node, core.LatencySample{PoPCode: "a", RTT: 12 * time.Millisecond})
	if got, _ := f.db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(resp.NodeToken)); got.AssignedPoP.PoPCode != "a" {
		t.Fatalf("home moved without cause: %s", got.AssignedPoP.PoPCode)
	}

	// Total loss on the home moves the node, and the move is persisted.
	if primary := svc.ReportProbe(ctx, node, core.LatencySample{PoPCode: "a", RTT: 500 * time.Millisecond, PacketLoss: 1}); primary != "b" {
		t.Fatalf("expected b after loss on a, got %q", primary)
	}
	if got, _ := f.db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(resp.NodeToken)); got.AssignedPoP == nil || got.AssignedPoP.PoPCode != "b" {
		t.Fatalf("new home not persisted: %+v", got.AssignedPoP)
	}
}
