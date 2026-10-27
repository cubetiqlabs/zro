package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
)

func TestScopedAPIKeys(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Tenants.Create(ctx, &core.Tenant{ID: uuid.New(), Name: "a", Slug: "acme", APIKey: "owner-key", IsActive: true})
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	call := func(method, path, key, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	mint := func(scope string, hours int) (string, string) {
		code, body := call("POST", "/api/v1/keys", "owner-key", `{"name":"`+scope+`-key","scope":"`+scope+`","expires_in_hours":`+strconv.Itoa(hours)+`}`)
		var out apiKeyResponse
		_ = json.Unmarshal([]byte(body), &out)
		if code != http.StatusCreated || !strings.HasPrefix(out.Key, "zro_key_") {
			t.Fatalf("create %s key: %d %s", scope, code, body)
		}
		return out.Key, out.ID.String()
	}
	read, _ := mint(core.ScopeRead, 0)
	write, writeID := mint(core.ScopeWrite, 24)
	admin, _ := mint(core.ScopeAdmin, 0)

	// The scope matrix: reads, writes, key management.
	for _, c := range []struct {
		key, method, path, body string
		want                    int
	}{
		{read, "GET", "/api/v1/networks", "", http.StatusOK},
		{read, "POST", "/api/v1/networks", `{"name":"n"}`, http.StatusForbidden},
		{write, "POST", "/api/v1/networks", `{"name":"n"}`, http.StatusCreated},
		{write, "GET", "/api/v1/keys", "", http.StatusForbidden},
		{write, "POST", "/api/v1/keys", `{"name":"x","scope":"admin"}`, http.StatusForbidden},
		{admin, "GET", "/api/v1/keys", "", http.StatusOK},
		{"owner-key", "GET", "/api/v1/keys", "", http.StatusOK},
		{"nope", "GET", "/api/v1/networks", "", http.StatusUnauthorized},
	} {
		if code, body := call(c.method, c.path, c.key, c.body); code != c.want {
			t.Errorf("%s %s with %.12s…: %d, want %d (%s)", c.method, c.path, c.key, code, c.want, body)
		}
	}
	if code, _ := call("POST", "/api/v1/keys", admin, `{"name":"x","scope":"root"}`); code != http.StatusBadRequest {
		t.Errorf("bad scope: %d", code)
	}

	// Listing never shows key material.
	if _, body := call("GET", "/api/v1/keys", admin, ""); strings.Contains(body, "zro_key_") || strings.Contains(body, "key_hash") {
		t.Fatalf("key list leaks keys: %s", body)
	}

	// Audit names the key that acted.
	tenant, _ := db.Tenants.GetByAPIKey(ctx, "owner-key")
	events, _ := db.Audit.List(ctx, tenant.ID, "", time.Time{}, 100)
	found := false
	for _, e := range events {
		found = found || (e.Action == "network.create" && e.Actor == "tenant:acme/key:write-key")
	}
	if !found {
		t.Errorf("audit does not name the scoped key: %+v", events)
	}

	// Revoked and expired keys stop working.
	if code, _ := call("DELETE", "/api/v1/keys/"+writeID, admin, ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := call("GET", "/api/v1/networks", write, ""); code != http.StatusUnauthorized {
		t.Errorf("revoked key works: %d", code)
	}
	k, _ := db.APIKeys.GetByHash(ctx, core.HashAPIKey(read))
	past := time.Now().Add(-time.Second)
	k.ExpiresAt = &past
	_ = db.DB.Save(k).Error
	if code, _ := call("GET", "/api/v1/networks", read, ""); code != http.StatusUnauthorized {
		t.Errorf("expired key works: %d", code)
	}
}
