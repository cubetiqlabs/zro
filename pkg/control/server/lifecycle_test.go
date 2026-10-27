package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/store"
)

func TestNodeLifecycleAndAudit(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "lifecycle-secret"
	srv := NewServer(&config.ControlPlaneConfig{
		SecretKey: secret, AdminAPIKey: "admin-key", RequireAuth: true,
		DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64",
	}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	do := func(method, path, bearer string, body any) (int, []byte) {
		b, _ := json.Marshal(body)
		if body == nil {
			b = nil
		}
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	mkTenant := func(slug string) string {
		_, body := do("POST", "/api/v1/tenants", "admin-key", map[string]string{"name": slug, "slug": slug})
		var out tenantResponse
		_ = json.Unmarshal(body, &out)
		return out.APIKey
	}
	key, otherKey := mkTenant("acme"), mkTenant("other")
	_, body := do("POST", "/api/v1/networks", key, CreateNetworkRequest{Name: "n"})
	var nw core.Network
	_ = json.Unmarshal(body, &nw)

	enroll := func(host string, tags ...string) EnrollResponse {
		kp, _ := crypto.GenerateKeyPair()
		tok := crypto.GenerateEnrollmentToken(secret, nw.ID, host, time.Hour, kp.PublicKey)
		code, body := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: tok, PublicKey: kp.PublicKey, Hostname: host, Tags: tags})
		var resp EnrollResponse
		_ = json.Unmarshal(body, &resp)
		if code != http.StatusOK {
			t.Fatalf("enroll %s: %d %s", host, code, body)
		}
		return resp
	}
	peersOf := func(token string) (int, []core.Node) {
		code, body := do("GET", "/api/v1/network/"+nw.ID+"/peers", token, nil)
		var peers []core.Node
		_ = json.Unmarshal(body, &peers)
		return code, peers
	}
	a := enroll("a")

	// Approval: a new node is held out of the mesh until approved.
	if code, _ := do("PATCH", "/api/v1/networks/"+nw.ID, key, map[string]any{"approval_required": true}); code != http.StatusOK {
		t.Fatalf("enable approval: %d", code)
	}
	b := enroll("b", "tag:web")
	if _, peers := peersOf(a.NodeToken); len(peers) != 1 {
		t.Fatalf("pending node is visible to peers: %d peers", len(peers))
	}
	if code, peers := peersOf(b.NodeToken); code != http.StatusOK || len(peers) != 0 {
		t.Fatalf("pending node sees peers: %d %d", code, len(peers))
	}
	if code, _ := do("POST", "/api/v1/nodes/"+b.NodeID.String()+"/approve", otherKey, nil); code != http.StatusNotFound {
		t.Fatalf("other tenant approve: %d", code)
	}
	if code, _ := do("POST", "/api/v1/nodes/"+b.NodeID.String()+"/approve", key, nil); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	if _, peers := peersOf(a.NodeToken); len(peers) != 2 {
		t.Fatalf("approved node missing: %d peers", len(peers))
	}

	// Plane-set tags survive the node re-joining with its own.
	if code, body := do("PATCH", "/api/v1/nodes/"+b.NodeID.String(), key, map[string]any{"tags": []string{"tag:db", "tag:db"}}); code != http.StatusOK {
		t.Fatalf("set tags: %d %s", code, body)
	}
	node, _ := db.Nodes.GetByID(t.Context(), b.NodeID)
	if len(node.Tags) != 1 || node.Tags[0] != "tag:db" || !node.TagsManaged {
		t.Fatalf("tags: %+v", node)
	}
	if code, _ := do("PATCH", "/api/v1/nodes/"+b.NodeID.String(), key, map[string]any{"tags": []string{"bad tag"}}); code != http.StatusBadRequest {
		t.Fatalf("invalid tag accepted: %d", code)
	}

	// Disable: the node can no longer authenticate and drops out of the mesh.
	if code, _ := do("PATCH", "/api/v1/nodes/"+b.NodeID.String(), key, map[string]any{"disabled": true}); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := peersOf(b.NodeToken); code != http.StatusUnauthorized {
		t.Fatalf("disabled node authenticated: %d", code)
	}
	if _, peers := peersOf(a.NodeToken); len(peers) != 1 {
		t.Fatalf("disabled node still a peer: %d", len(peers))
	}

	// Key expiry: an expired node is refused.
	if code, _ := do("PATCH", "/api/v1/networks/"+nw.ID, key, map[string]any{"approval_required": false, "key_expiry_hours": 1}); code != http.StatusOK {
		t.Fatalf("set expiry: %d", code)
	}
	c := enroll("c")
	n, _ := db.Nodes.GetByID(t.Context(), c.NodeID)
	if n.ExpiresAt == nil || time.Until(*n.ExpiresAt) < 59*time.Minute {
		t.Fatalf("expiry not set: %v", n.ExpiresAt)
	}
	past := time.Now().Add(-time.Minute)
	n.ExpiresAt = &past
	_ = db.Nodes.Update(t.Context(), n)
	if code, body := do("GET", "/api/v1/network/"+nw.ID+"/peers", c.NodeToken, nil); code != http.StatusUnauthorized || !bytes.Contains(body, []byte("expired")) {
		t.Fatalf("expired node: %d %s", code, body)
	}

	// The audit trail has every change, scoped to the tenant.
	_, body = do("GET", "/api/v1/audit?network_id="+nw.ID, key, nil)
	var events []core.AuditEvent
	_ = json.Unmarshal(body, &events)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
		if e.Actor != "tenant:acme" {
			t.Errorf("actor %q", e.Actor)
		}
	}
	for _, want := range []string{"network.create", "network.update", "node.approve", "node.update"} {
		if !seen[want] {
			t.Errorf("audit is missing %s: %s", want, body)
		}
	}
	_, body = do("GET", "/api/v1/audit", otherKey, nil)
	var others []core.AuditEvent
	_ = json.Unmarshal(body, &others)
	for _, e := range others {
		if e.NetworkID == nw.ID || e.Target == "acme" {
			t.Fatalf("other tenant sees acme's events: %s", body)
		}
	}
	if code, _ := do("GET", "/api/v1/audit?network_id="+nw.ID, otherKey, nil); code != http.StatusForbidden {
		t.Fatalf("other tenant reads network audit: %d", code)
	}
}
