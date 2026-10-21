package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/store"
)

func TestHealthReadinessAndMetrics(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", AdminAPIKey: "admin"}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func(path, bearer string) (int, string) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := get("/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz: %d", code)
	}
	if code, _ := get("/readyz", ""); code != http.StatusOK {
		t.Fatalf("/readyz with a live database: %d", code)
	}

	// Metrics expose mesh-wide counts: admin only.
	if code, _ := get("/metrics", ""); code != http.StatusUnauthorized {
		t.Fatalf("/metrics without the admin key: %d", code)
	}
	code, body := get("/metrics", "admin")
	if code != http.StatusOK || !strings.Contains(body, "zro_nodes 0") || !strings.Contains(body, "zro_build_info{") || !strings.Contains(body, "# TYPE zro_edge_pops_healthy gauge") {
		t.Fatalf("/metrics: %d\n%s", code, body)
	}

	// Without an admin key configured the endpoint does not exist.
	bare := httptest.NewServer(NewServer(&config.ControlPlaneConfig{SecretKey: "s"}, db).Handler())
	defer bare.Close()
	resp, _ := http.Get(bare.URL + "/metrics")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/metrics with no admin key must be 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// A database that went away makes the replica unready, not dead.
	sqlDB, _ := db.DB.DB()
	_ = sqlDB.Close()
	if code, _ := get("/readyz", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with a closed database: %d", code)
	}
	if code, _ := get("/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz must stay up while the database is down: %d", code)
	}
}
