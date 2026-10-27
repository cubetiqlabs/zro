package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// tenantByKey resolves a tenant API key: the tenant's own key (admin scope)
// or a scoped key that has not expired.
func (s *Server) tenantByKey(ctx context.Context, key string) (tenant *core.Tenant, scope, keyName string, ok bool) {
	if t, err := s.db.Tenants.GetByAPIKey(ctx, key); err == nil && t != nil {
		return t, core.ScopeAdmin, "", t.IsActive
	}
	k, err := s.db.APIKeys.GetByHash(ctx, core.HashAPIKey(key))
	if err != nil || k == nil {
		return nil, "", "", false
	}
	now := time.Now()
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return nil, "", "", false
	}
	t, err := s.db.Tenants.GetByID(ctx, k.TenantID)
	if err != nil || t == nil || !t.IsActive {
		return nil, "", "", false
	}
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute { // one write a minute per key, not per request
		_ = s.db.APIKeys.Touch(ctx, k.ID, now)
	}
	return t, k.Scope, k.Name, true
}

// requireAdminScope guards key management and node approval.
func requireAdminScope(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sub := controlauth.FromContext(r.Context()); sub == nil || !core.ScopeAllows(sub.Scope, core.ScopeAdmin) {
			apiError(w, "forbidden: this needs an admin-scoped API key", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// methodScope is the scope a request needs: reads need read, the rest write.
func methodScope(r *http.Request) string {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return core.ScopeRead
	}
	return core.ScopeWrite
}

type createKeyRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Hours int    `json:"expires_in_hours"` // 0 = never
}

// apiKeyResponse carries the plaintext key only when it is created.
type apiKeyResponse struct {
	core.APIKey
	Key string `json:"key,omitempty"`
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		apiError(w, "name is required (at most 100 characters)", http.StatusBadRequest)
		return
	}
	if !core.ScopeAllows(req.Scope, req.Scope) {
		apiError(w, "scope must be read, write or admin", http.StatusBadRequest)
		return
	}
	if req.Hours < 0 || req.Hours > 24*366 {
		apiError(w, "expires_in_hours must be between 0 (never) and 8784", http.StatusBadRequest)
		return
	}
	plain, _, err := controlauth.GenerateToken("zro_key_")
	if err != nil {
		apiError(w, "failed to generate API key", http.StatusInternalServerError)
		return
	}
	tenant := TenantFromContext(r.Context())
	key := core.APIKey{ID: uuid.New(), TenantID: tenant.ID, Name: req.Name, KeyHash: core.HashAPIKey(plain), Scope: req.Scope, CreatedAt: time.Now()}
	if req.Hours > 0 {
		exp := key.CreatedAt.Add(time.Duration(req.Hours) * time.Hour)
		key.ExpiresAt = &exp
	}
	if err := s.db.APIKeys.Create(r.Context(), &key); err != nil {
		apiError(w, "failed to store API key", http.StatusInternalServerError)
		return
	}
	expires := "never"
	if key.ExpiresAt != nil {
		expires = key.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.audit(r, tenant.ID, "", "key.create", key.Name, "scope="+key.Scope+" expires="+expires)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, apiKeyResponse{APIKey: key, Key: plain})
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.db.APIKeys.ListByTenant(r.Context(), TenantFromContext(r.Context()).ID)
	if err != nil {
		apiError(w, "failed to list API keys", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []core.APIKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid key id", http.StatusBadRequest)
		return
	}
	tenant := TenantFromContext(r.Context())
	if err := s.db.APIKeys.Delete(r.Context(), tenant.ID, id); err != nil {
		apiError(w, "key not found", http.StatusNotFound)
		return
	}
	s.audit(r, tenant.ID, "", "key.delete", id.String(), "")
	w.WriteHeader(http.StatusNoContent)
}
