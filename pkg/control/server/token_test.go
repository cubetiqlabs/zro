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
