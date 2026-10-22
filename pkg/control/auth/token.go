// Package auth contains shared authentication primitives for the ZRO control
// plane. It is deliberately small so the REST server, gRPC server, and client
// agents all agree on how node tokens are generated, hashed, and identified.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// Kind identifies which principal authenticated a request.
type Kind string

const (
	KindNode   Kind = "node"
	KindTenant Kind = "tenant"
	KindEdge   Kind = "edge"
)

// Subject is the authenticated principal attached to a request context.
type Subject struct {
	Kind   Kind
	Node   *core.Node
	Tenant *core.Tenant
	// PoPCode is set for an edge authenticated with its own per-PoP credential.
	// An edge using only the shared registration key has no PoPCode and may
	// only claim PoPs.
	PoPCode string
}

// NetworkID returns the network a node principal is bound to.
func (s *Subject) NetworkID() string {
	if s != nil && s.Node != nil {
		return s.Node.NetworkID
	}
	return ""
}

// TenantID returns the tenant a tenant principal belongs to.
func (s *Subject) TenantID() uuid.UUID {
	if s != nil && s.Tenant != nil {
		return s.Tenant.ID
	}
	return uuid.Nil
}

type subjectKey struct{}

// WithSubject stores an authenticated subject in a context.
func WithSubject(ctx context.Context, subject *Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, subject)
}

// FromContext returns the authenticated subject, if any.
func FromContext(ctx context.Context) *Subject {
	if subject, ok := ctx.Value(subjectKey{}).(*Subject); ok {
		return subject
	}
	return nil
}

// NodeFromContext returns the authenticated node, if the principal is a node.
func NodeFromContext(ctx context.Context) *core.Node {
	if subject := FromContext(ctx); subject != nil {
		return subject.Node
	}
	return nil
}

// TenantFromContext returns the authenticated tenant, if the principal is a tenant.
func TenantFromContext(ctx context.Context) *core.Tenant {
	if subject := FromContext(ctx); subject != nil {
		return subject.Tenant
	}
	return nil
}

// GenerateToken creates a high-entropy bearer token and its storage hash.
func GenerateToken(prefix string) (token string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = prefix + hex.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns a stable, non-reversible representation of a bearer token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// BearerToken extracts a bearer token from the Authorization header.
func BearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) >= 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	if len(header) >= 7 && strings.EqualFold(header[:7], "ApiKey ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// TenantKey extracts a tenant API key from common REST header locations.
func TenantKey(r *http.Request) string {
	if key := BearerToken(r); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}
	return ""
}

// NodeToken extracts a node bearer token from request headers. Credentials in
// the query string are deliberately unsupported: URLs end up in logs.
func NodeToken(r *http.Request) string {
	if token := BearerToken(r); token != "" {
		return token
	}
	if token := strings.TrimSpace(r.Header.Get("X-Node-Token")); token != "" {
		return token
	}
	return ""
}

// EdgeKey extracts an edge API key from request headers.
func EdgeKey(r *http.Request) string {
	if key := BearerToken(r); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("X-Edge-Key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}
	return ""
}
