package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
)

func TestPolicyShorthandReplaceAndTest(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"key-a", "key-b"} {
		_ = db.Tenants.Create(ctx, &core.Tenant{ID: uuid.New(), Name: key, Slug: key, APIKey: key, IsActive: true})
	}
	ta, _ := db.Tenants.GetByAPIKey(ctx, "key-a")
	nw := &core.Network{ID: core.GenerateNetworkID(), TenantID: ta.ID, Name: "n", Slug: "n", IPv4CIDR: "100.64.0.0/16", IsActive: true}
	_ = db.Networks.Create(ctx, nw)
	for host, ip := range map[string]string{"web-1": "100.64.0.2", "db-1": "100.64.0.3"} {
		tags := core.StringList{"tag:" + strings.TrimSuffix(host, "-1")}
		_ = db.Nodes.Create(ctx, &core.Node{ID: uuid.New(), NetworkID: nw.ID, Hostname: host, PublicKey: host, OverlayIPv4: ip, Tags: tags, IsActive: true})
	}

	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	call := func(method, path, key, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Shorthand: a hostname resolves to its overlay IP, a service to its port.
	code, body := call("POST", "/api/v1/acl/rules", "key-a", `{"network_id":"`+nw.ID+`","name":"web to db","from":"tag:web","to":"db-1","ports":"postgres"}`)
	var rule core.ACLRule
	_ = json.Unmarshal([]byte(body), &rule)
	if code != http.StatusCreated || rule.SourceTag != "tag:web" || rule.DestIP != "100.64.0.3" || rule.Ports != "5432" || rule.Protocol != "tcp" {
		t.Fatalf("shorthand create: %d %s", code, body)
	}
	if code, _ := call("POST", "/api/v1/acl/rules", "key-a", `{"network_id":"`+nw.ID+`","to":"nope"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown host: %d", code)
	}
	if code, _ := call("POST", "/api/v1/acl/rules", "key-b", `{"network_id":"`+nw.ID+`"}`); code != http.StatusForbidden {
		t.Fatalf("other tenant create: %d", code)
	}

	// PATCH: new ports bring their own protocol.
	code, body = call("PATCH", "/api/v1/acl/rules/"+rule.ID.String(), "key-a", `{"ports":"dns","action":"deny"}`)
	_ = json.Unmarshal([]byte(body), &rule)
	if code != http.StatusOK || rule.Ports != "53" || rule.Protocol != "*" || rule.Action != core.ACLActionDeny || rule.Name != "web to db" {
		t.Fatalf("patch: %d %s", code, body)
	}
	if code, _ := call("PATCH", "/api/v1/acl/rules/"+rule.ID.String(), "key-b", `{"action":"ALLOW"}`); code != http.StatusNotFound {
		t.Fatalf("other tenant patch: %d", code)
	}

	// PUT with one bad rule changes nothing.
	policy := "/api/v1/networks/" + nw.ID + "/policy"
	if code, _ := call("PUT", policy, "key-a", `{"rules":[{"from":"tag:admin"},{"ports":"22/sctp"}]}`); code != http.StatusBadRequest {
		t.Fatalf("bad PUT: %d", code)
	}
	if rules, _ := db.ACLs.ListByNetworkID(ctx, nw.ID); len(rules) != 1 {
		t.Fatalf("bad PUT changed the policy: %d rules", len(rules))
	}
	code, body = call("PUT", policy, "key-a", `{"rules":[
		{"name":"no ssh to db","to":"tag:db","ports":"ssh","action":"DENY","priority":5},
		{"name":"web to db","from":"web-1","to":"tag:db","ports":"postgres"}]}`)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, body)
	}
	if rules, _ := db.ACLs.ListByNetworkID(ctx, nw.ID); len(rules) != 2 {
		t.Fatalf("PUT: %d rules", len(rules))
	}
	code, body = call("GET", policy, "key-a", "")
	if code != http.StatusOK || !strings.Contains(body, `"name":"no ssh to db"`) {
		t.Fatalf("GET policy: %d %s", code, body)
	}

	// The test endpoint resolves hostnames and their tags.
	verdict := func(from, to, port string) string {
		code, body := call("POST", policy+"/test", "key-a", `{"from":"`+from+`","to":"`+to+`","port":"`+port+`"}`)
		var res PolicyTestResult
		_ = json.Unmarshal([]byte(body), &res)
		if code != http.StatusOK {
			t.Fatalf("test %s->%s:%s: %d %s", from, to, port, code, body)
		}
		return res.Verdict
	}
	if v := verdict("web-1", "db-1", "postgres"); v != "allow" {
		t.Errorf("web-1 -> db-1 postgres: %s", v)
	}
	if v := verdict("web-1", "db-1", "ssh"); v != "deny" {
		t.Errorf("web-1 -> db-1 ssh: %s", v)
	}
	if v := verdict("db-1", "web-1", "https"); v != "node-policy" {
		t.Errorf("db-1 -> web-1 https: %s", v)
	}
}
