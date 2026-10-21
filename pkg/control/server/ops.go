package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	controlauth "github.com/cubis/zro/pkg/control/auth"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/version"
)

// handleLive is the liveness probe: the process is up and serving.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "zro-plane", "version": version.Get().Version})
}

// handleReady is the readiness probe: the plane can reach its database, so a
// load balancer should stop sending traffic to a replica that cannot.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	sqlDB, err := s.db.DB.DB()
	if err == nil {
		err = sqlDB.PingContext(ctx)
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "reason": "database unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

// handleMetrics serves Prometheus text format. It exposes mesh-wide counts, so
// it requires the admin key and is off when none is configured.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	expected := s.cfg.AdminAPIKey
	if expected == "" {
		http.NotFound(w, r)
		return
	}
	key := controlauth.BearerToken(r)
	if subtle.ConstantTimeCompare([]byte(key), []byte(expected)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	count := func(model any, where string, args ...any) int64 {
		var n int64
		q := s.db.WithContext(ctx).Model(model)
		if where != "" {
			q = q.Where(where, args...)
		}
		q.Count(&n)
		return n
	}

	var b strings.Builder
	gauge := func(name, help string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	gauge("zro_nodes", "Enrolled nodes.", count(&core.Node{}, ""))
	gauge("zro_nodes_active", "Enrolled nodes marked active.", count(&core.Node{}, "is_active = ?", true))
	gauge("zro_networks", "Overlay networks.", count(&core.Network{}, ""))
	gauge("zro_tenants", "Tenants.", count(&core.Tenant{}, ""))
	gauge("zro_tunnels", "Registered ingress tunnels.", count(&core.Tunnel{}, ""))
	gauge("zro_acl_rules", "Network access rules.", count(&core.ACLRule{}, ""))
	gauge("zro_edge_pops", "Registered edge PoPs.", count(&core.EdgePoP{}, ""))
	gauge("zro_edge_pops_healthy", "Edge PoPs currently healthy.", count(&core.EdgePoP{}, "is_healthy = ?", true))
	gauge("zro_event_subscribers", "Connected event stream subscribers (SSE, WebSocket, gRPC).", int64(s.bus.Len()))

	v := version.Get()
	fmt.Fprintf(&b, "# HELP zro_build_info Build information.\n# TYPE zro_build_info gauge\nzro_build_info{version=%q,commit=%q,go=%q} 1\n", v.Version, v.Commit, v.Go)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
