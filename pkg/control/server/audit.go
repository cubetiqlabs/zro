package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// audit records a successful change. tenantID may be uuid.Nil for changes
// that belong to no tenant (edge PoPs). A failed write is logged, never
// returned: the change itself already happened.
func (s *Server) audit(r *http.Request, tenantID uuid.UUID, networkID, action, target, detail string) {
	ev := &core.AuditEvent{
		ID: uuid.New(), TenantID: tenantID, NetworkID: networkID,
		Actor: actorOf(r), Action: action, Target: target, Detail: detail,
		SourceIP: sourceIP(r), CreatedAt: time.Now(),
	}
	if err := s.db.Audit.Create(r.Context(), ev); err != nil {
		slog.Warn("Could not write audit event", "action", action, "error", err)
	}
}

// auditNetwork records a change to something inside network.
func (s *Server) auditNetwork(r *http.Request, network *core.Network, action, target, detail string) {
	s.audit(r, network.TenantID, network.ID, action, target, detail)
}

func actorOf(r *http.Request) string {
	sub := controlauth.FromContext(r.Context())
	switch {
	case sub == nil && r.Header.Get("X-Cluster-Secret") != "":
		return "cluster-secret" // only reached once the secret was verified
	case sub == nil:
		return "admin" // admin routes authenticate without a subject
	case sub.Tenant != nil:
		return "tenant:" + sub.Tenant.Slug
	case sub.Node != nil:
		return "node:" + sub.Node.Hostname
	case sub.PoPCode != "":
		return "edge:" + sub.PoPCode
	}
	return string(sub.Kind)
}

// sourceIP is the peer address of the request.
// ponytail: behind a proxy or CDN this is the proxy; add a trusted-proxy
// setting before reading X-Forwarded-For, which clients can forge.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleListAudit returns the tenant's audit trail, newest first. Page with
// ?before=<RFC3339 created_at of the last event seen>.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	tenant := controlauth.FromContext(r.Context()).TenantID()
	q := r.URL.Query()
	if id := q.Get("network_id"); id != "" {
		if _, ok := s.ownedNetwork(w, r, id); !ok {
			return
		}
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			apiError(w, "limit must be between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = n
	}
	var before time.Time
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			apiError(w, "before must be an RFC 3339 time", http.StatusBadRequest)
			return
		}
		before = t
	}
	events, err := s.db.Audit.List(r.Context(), tenant, q.Get("network_id"), before, limit)
	if err != nil {
		apiError(w, "failed to read the audit log", http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []core.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// nodeForRequest loads the node in the path, hiding other tenants' nodes as missing.
func (s *Server) nodeForRequest(w http.ResponseWriter, r *http.Request) (*core.Node, *core.Network, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid node id", http.StatusBadRequest)
		return nil, nil, false
	}
	node, err := s.db.Nodes.GetByID(r.Context(), id)
	if err != nil || node == nil {
		apiError(w, "node not found", http.StatusNotFound)
		return nil, nil, false
	}
	network, ok := s.authorizeNetwork(r.Context(), node.NetworkID)
	if !ok {
		apiError(w, "node not found", http.StatusNotFound)
		return nil, nil, false
	}
	return node, network, true
}

// handleUpdateNode sets a node's tags (the plane's tags then win over the
// node's own on re-join) or switches it off and on.
func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	node, network, ok := s.nodeForRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		Tags     *[]string `json:"tags"`
		Disabled *bool     `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	var changes []string
	if req.Tags != nil {
		tags := slices.Compact(slices.Sorted(slices.Values(*req.Tags)))
		for _, t := range tags {
			if t == "" || len(t) > 100 || strings.ContainsAny(t, " ,\t\n") {
				apiError(w, "tags must be non-empty words without spaces or commas, at most 100 characters", http.StatusBadRequest)
				return
			}
		}
		node.Tags, node.TagsManaged = tags, true
		changes = append(changes, "tags="+strings.Join(tags, ","))
	}
	if req.Disabled != nil {
		node.Disabled = *req.Disabled
		changes = append(changes, "disabled="+strconv.FormatBool(node.Disabled))
	}
	if len(changes) == 0 {
		apiError(w, "nothing to change: give tags or disabled", http.StatusBadRequest)
		return
	}
	node.UpdatedAt = time.Now()
	if err := s.db.Nodes.Update(r.Context(), node); err != nil {
		apiError(w, "failed to update node", http.StatusInternalServerError)
		return
	}
	s.svc.NodeChanged(r.Context(), node)
	s.auditNetwork(r, network, "node.update", node.Hostname, strings.Join(changes, " "))
	writeJSON(w, http.StatusOK, node)
}

// handleApproveNode admits a node held for approval.
func (s *Server) handleApproveNode(w http.ResponseWriter, r *http.Request) {
	node, network, ok := s.nodeForRequest(w, r)
	if !ok {
		return
	}
	if node.Pending {
		node.Pending, node.UpdatedAt = false, time.Now()
		if err := s.db.Nodes.Update(r.Context(), node); err != nil {
			apiError(w, "failed to approve node", http.StatusInternalServerError)
			return
		}
		s.svc.NodeChanged(r.Context(), node)
		s.auditNetwork(r, network, "node.approve", node.Hostname, "")
	}
	writeJSON(w, http.StatusOK, node)
}
