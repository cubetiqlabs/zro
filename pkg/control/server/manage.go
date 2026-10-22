package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	controlevents "github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/control/service"
	"github.com/google/uuid"
)

// handleUpdateNetwork renames a network or changes its DNS domain / active flag.
// Addressing (CIDRs) is immutable: changing it would orphan allocated addresses.
func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	network, ok := s.authorizeNetwork(r.Context(), r.PathValue("id"))
	if !ok {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	var req struct {
		Name      *string `json:"name"`
		DNSDomain *string `json:"dns_domain"`
		IsActive  *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			apiError(w, "name must not be empty", http.StatusBadRequest)
			return
		}
		network.Name = *req.Name
	}
	if req.DNSDomain != nil {
		if !service.ValidHostname(strings.ToLower(*req.DNSDomain)) {
			apiError(w, "dns_domain must be a valid DNS name", http.StatusBadRequest)
			return
		}
		network.DNSDomain = strings.ToLower(*req.DNSDomain)
	}
	if req.IsActive != nil {
		network.IsActive = *req.IsActive
	}
	network.UpdatedAt = time.Now()
	if err := s.db.Networks.Update(r.Context(), network); err != nil {
		apiError(w, "failed to update network", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, network)
}

// handleDeleteNetwork removes an empty network and its access rules.
func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	network, ok := s.authorizeNetwork(r.Context(), r.PathValue("id"))
	if !ok {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	nodes, err := s.db.Nodes.ListByNetworkID(r.Context(), network.ID)
	if err != nil {
		apiError(w, "failed to check network members", http.StatusInternalServerError)
		return
	}
	if len(nodes) > 0 {
		apiError(w, "network still has nodes; remove them first", http.StatusConflict)
		return
	}
	if rules, err := s.db.ACLs.ListByNetworkID(r.Context(), network.ID); err == nil {
		for _, rule := range rules {
			_ = s.db.ACLs.Delete(r.Context(), rule.ID)
		}
	}
	if err := s.db.Networks.Delete(r.Context(), network.ID); err != nil {
		apiError(w, "failed to delete network", http.StatusInternalServerError)
		return
	}
	s.svc.ForgetNetwork(network.ID)
	w.WriteHeader(http.StatusNoContent)
}

// handleListNodes lists the members of a network the tenant owns.
func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	networkID := r.URL.Query().Get("network_id")
	if _, ok := s.authorizeNetwork(r.Context(), networkID); !ok {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	nodes, err := s.db.Nodes.ListByNetworkID(r.Context(), networkID)
	if err != nil {
		apiError(w, "failed to list nodes", http.StatusInternalServerError)
		return
	}
	writePage(w, r, nodes)
}

// handleDeleteNode removes a node of a network the tenant owns.
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	node, err := s.db.Nodes.GetByID(r.Context(), id)
	if err != nil || node == nil {
		apiError(w, "node not found", http.StatusNotFound)
		return
	}
	// A node of another tenant looks the same as a missing one.
	if _, ok := s.authorizeNetwork(r.Context(), node.NetworkID); !ok {
		apiError(w, "node not found", http.StatusNotFound)
		return
	}
	if err := s.svc.Deregister(r.Context(), node); err != nil {
		writeServiceError(w, err)
		return
	}
	if s.cfg.EnableGateway {
		_ = s.syncInternalGateway(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDeletePoP removes an edge PoP (admin).
func (s *Server) handleDeletePoP(w http.ResponseWriter, r *http.Request) {
	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), r.PathValue("code"))
	if err != nil || pop == nil {
		apiError(w, "pop not found", http.StatusNotFound)
		return
	}
	if err := s.db.EdgePoPs.Delete(r.Context(), pop.ID); err != nil {
		apiError(w, "failed to delete pop", http.StatusInternalServerError)
		return
	}
	s.broadcastDelta(controlevents.Scope{}, map[string]any{"event": "pop_status_changed", "pop_code": pop.PoPCode, "is_healthy": false, "status": "removed"})
	s.broadcastDelta(controlevents.Scope{}, map[string]any{"event": "mesh_graph_updated"})
	w.WriteHeader(http.StatusNoContent)
}

// handleGetNetwork returns one network the tenant owns.
func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	network, ok := s.authorizeNetwork(r.Context(), r.PathValue("id"))
	if !ok {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, network)
}

// handleGetNode returns one node of a network the tenant owns.
func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	node, err := s.db.Nodes.GetByID(r.Context(), id)
	if err != nil || node == nil {
		apiError(w, "node not found", http.StatusNotFound)
		return
	}
	// A node of another tenant looks the same as a missing one.
	if _, ok := s.authorizeNetwork(r.Context(), node.NetworkID); !ok {
		apiError(w, "node not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

// handleGetPoP returns one edge PoP (public, like the PoP list).
func (s *Server) handleGetPoP(w http.ResponseWriter, r *http.Request) {
	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), r.PathValue("code"))
	if err != nil || pop == nil {
		apiError(w, "pop not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, pop)
}

// handleGetTenant returns one tenant (admin); the API key is never included.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	tenant, err := s.db.Tenants.GetByID(r.Context(), id)
	if err != nil || tenant == nil {
		apiError(w, "tenant not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, toTenantResponse(tenant, false))
}

// handleGetACLRule returns one rule of a network the tenant owns.
func (s *Server) handleGetACLRule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid rule id", http.StatusBadRequest)
		return
	}
	rule, err := s.db.ACLs.GetByID(r.Context(), id)
	if err != nil || rule == nil {
		apiError(w, "rule not found", http.StatusNotFound)
		return
	}
	if _, ok := s.authorizeNetwork(r.Context(), rule.NetworkID); !ok {
		apiError(w, "rule not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}
