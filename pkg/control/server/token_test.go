package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
)

func TestCreateEnrollmentToken(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	mkTenant := func(slug, key string) *core.Tenant {
		tn := &core.Tenant{ID: uuid.New(), Name: slug, Slug: slug, APIKey: key, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		_ = db.Tenants.Create(ctx, tn)
		return tn
	}
	a, _ := mkTenant("a", "key-a"), mkTenant("b", "key-b")
	nw := &core.Network{ID: core.GenerateNetworkID(), TenantID: a.ID, Name: "n", Slug: "n", IPv4CIDR: "100.64.0.0/16", IPv6CIDR: "fd00:cafe:1::/64", IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = db.Networks.Create(ctx, nw)

	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s3cret", PublicURL: "https://plane.example", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	post := func(key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/networks/"+nw.ID+"/tokens", bytes.NewReader([]byte(body)))
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := post("key-a", "") // empty body = defaults
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Token, JoinCommand string }
	_ = json.Unmarshal(rec.Body.Bytes(), &struct {
		Token       *string `json:"token"`
		JoinCommand *string `json:"join_command"`
	}{&out.Token, &out.JoinCommand})
	kp, _ := crypto.GenerateKeyPair()
	if _, err := crypto.VerifyEnrollmentToken("s3cret", out.Token, kp.PublicKey); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if !strings.HasPrefix(out.JoinCommand, "zro join --plane https://plane.example --token ") {
		t.Fatalf("join command: %q", out.JoinCommand)
	}

	if rec := post("key-b", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant: %d", rec.Code)
	}
	if rec := post("key-a", `{"hours":100000}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("hours clamp: %d", rec.Code)
	}
	if rec := post("key-a", `{"node_type":"admin"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("node_type: %d", rec.Code)
	}
}

func TestMintTokenWithClusterSecret(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	tn := &core.Tenant{ID: uuid.New(), Name: "a", Slug: "aa", APIKey: "key-a", IsActive: true}
	_ = db.Tenants.Create(ctx, tn)
	nw := &core.Network{ID: core.GenerateNetworkID(), TenantID: tn.ID, Name: "n", Slug: "n", IPv4CIDR: "100.64.0.0/16", IPv6CIDR: "fd00:cafe:1::/64", IsActive: true}
	_ = db.Networks.Create(ctx, nw)

	secret := "a-long-enough-cluster-secret-0123456789"
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: secret, PublicURL: "https://plane.example", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	post := func(sec, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(body))
		req.Header.Set("X-Cluster-Secret", sec)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := post(secret, `{"network_id":"`+nw.ID+`","hostname":"web-1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid secret: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	kp, _ := crypto.GenerateKeyPair()
	if _, err := crypto.VerifyEnrollmentToken(secret, out.Token, kp.PublicKey); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if rec := post(secret, `{"network_id":"0000000000000000"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown network: %d", rec.Code)
	}

	// Wrong secrets are refused, and after enough misses even the right one waits.
	for i := 0; i < secretMaxFails; i++ {
		if rec := post("nope", `{}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong secret: %d", rec.Code)
		}
	}
	if rec := post(secret, `{"network_id":"`+nw.ID+`"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttle: %d", rec.Code)
	}

	// The shipped placeholder secret never mints.
	weak := NewServer(&config.ControlPlaneConfig{SecretKey: crypto.DefaultSecretKey, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	req := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{}`))
	req.Header.Set("X-Cluster-Secret", crypto.DefaultSecretKey)
	wrec := httptest.NewRecorder()
	weak.Handler().ServeHTTP(wrec, req)
	if wrec.Code != http.StatusForbidden {
		t.Fatalf("default secret: %d", wrec.Code)
	}

	// The form is served with a CSP that forbids inline script.
	prec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(prec, httptest.NewRequest("GET", "/ui/tokens", nil))
	if prec.Code != http.StatusOK || !strings.Contains(prec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("form: %d %v", prec.Code, prec.Header())
	}
}
