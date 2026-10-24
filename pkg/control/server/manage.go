package server

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	controlevents "github.com/cubetiqlabs/zro/pkg/control/events"
	"github.com/cubetiqlabs/zro/pkg/control/service"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
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

const (
	defaultTokenHours = 24
	maxTokenHours     = 720
)

// handleCreateEnrollmentToken mints a node enrollment token for a network the
// tenant owns, so operators need neither the cluster secret nor the CLI.
func (s *Server) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	network, ok := s.authorizeNetwork(r.Context(), r.PathValue("id"))
	if !ok {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	req, ok := decodeTokenRequest(w, r)
	if !ok {
		return
	}
	s.mintEnrollmentToken(w, network, req)
}

// tokenRequest is the body of both token endpoints.
type tokenRequest struct {
	NetworkID string `json:"network_id"` // only read by POST /api/v1/tokens
	Hostname  string `json:"hostname"`
	NodeType  string `json:"node_type"`
	Hours     int    `json:"hours"`
	PubKey    string `json:"pubkey"`
}

// decodeTokenRequest reads the request body; an empty body means "all defaults".
func decodeTokenRequest(w http.ResponseWriter, r *http.Request) (tokenRequest, bool) {
	var req tokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && err != io.EOF {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// mintEnrollmentToken validates req and answers with a signed token for network.
func (s *Server) mintEnrollmentToken(w http.ResponseWriter, network *core.Network, req tokenRequest) {
	if req.Hours == 0 {
		req.Hours = defaultTokenHours
	}
	if req.Hours < 0 || req.Hours > maxTokenHours {
		apiError(w, fmt.Sprintf("hours must be between 1 and %d", maxTokenHours), http.StatusBadRequest)
		return
	}
	if req.NodeType == "" {
		req.NodeType = string(core.NodeTypePeer)
	}
	if req.NodeType != string(core.NodeTypePeer) && req.NodeType != string(core.NodeTypeGateway) {
		apiError(w, "node_type must be peer or gateway", http.StatusBadRequest)
		return
	}
	if req.Hostname != "" && !service.ValidHostname(strings.ToLower(req.Hostname)) {
		apiError(w, "hostname must be a valid DNS name", http.StatusBadRequest)
		return
	}
	if req.PubKey != "" {
		if err := crypto.ValidatePublicKey(req.PubKey); err != nil {
			apiError(w, "invalid pubkey", http.StatusBadRequest)
			return
		}
	}

	expires := time.Now().Add(time.Duration(req.Hours) * time.Hour)
	token, err := crypto.SignEnrollmentToken(s.cfg.SecretKey, crypto.EnrollmentTokenPayload{
		NetworkID: network.ID, Hostname: req.Hostname, NodeType: req.NodeType,
		BoundPublicKey: req.PubKey, Expiry: expires.Unix(),
	})
	if err != nil {
		apiError(w, "failed to sign token", http.StatusInternalServerError)
		return
	}
	join := "zro join --token " + token
	if s.cfg.PublicURL != "" {
		join = "zro join --plane " + s.cfg.PublicURL + " --token " + token
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "network_id": network.ID, "node_type": req.NodeType,
		"expires_at": expires.UTC(), "join_command": join,
	})
}

// secretGuard throttles failed cluster-secret attempts: after maxFails misses
// in a window every attempt is refused until it ends, which makes online
// guessing impractical. The cost is that an attacker can pause this one
// endpoint, never the rest of the API.
type secretGuard struct {
	mu    sync.Mutex
	start time.Time
	fails int
}

const (
	secretMaxFails = 10
	secretWindow   = time.Minute
)

func (g *secretGuard) blocked() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return time.Since(g.start) < secretWindow && g.fails >= secretMaxFails
}

func (g *secretGuard) fail() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.start) >= secretWindow {
		g.start, g.fails = time.Now(), 0
	}
	g.fails++
}

// handleMintTokenWithSecret mints a token for any network when the caller
// proves knowledge of the cluster secret, the same capability `zro token
// --secret` has offline.
func (s *Server) handleMintTokenWithSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.SecretKey == "" || s.cfg.SecretKey == crypto.DefaultSecretKey {
		apiError(w, "token minting by secret is disabled until control_plane.secret_key is set", http.StatusForbidden)
		return
	}
	if s.secretGuard.blocked() {
		w.Header().Set("Retry-After", "60")
		apiError(w, "too many failed attempts; retry later", http.StatusTooManyRequests)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Cluster-Secret")), []byte(s.cfg.SecretKey)) != 1 {
		s.secretGuard.fail()
		apiError(w, "invalid cluster secret", http.StatusUnauthorized)
		return
	}
	req, ok := decodeTokenRequest(w, r)
	if !ok {
		return
	}
	network, err := s.db.Networks.GetByID(r.Context(), req.NetworkID)
	if err != nil || network == nil {
		apiError(w, "network not found", http.StatusNotFound)
		return
	}
	s.mintEnrollmentToken(w, network, req)
}

//go:embed ui/tokens.html ui/tokens.js
var tokenUI embed.FS

// handleTokenPage serves the join-token form. The script is a separate file so
// the page can run under a CSP that forbids inline script.
func (s *Server) handleTokenPage(w http.ResponseWriter, r *http.Request) {
	serveUI(w, "ui/tokens.html", "text/html; charset=utf-8")
}

func (s *Server) handleTokenScript(w http.ResponseWriter, r *http.Request) {
	serveUI(w, "ui/tokens.js", "text/javascript; charset=utf-8")
}

func serveUI(w http.ResponseWriter, name, contentType string) {
	b, err := tokenUI.ReadFile(name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
