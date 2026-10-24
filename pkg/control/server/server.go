package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/api/openapi"
	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/config"
	controlacl "github.com/cubetiqlabs/zro/pkg/control/acl"
	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	controlevents "github.com/cubetiqlabs/zro/pkg/control/events"
	controlgrpc "github.com/cubetiqlabs/zro/pkg/control/grpc"
	"github.com/cubetiqlabs/zro/pkg/control/ipam"
	"github.com/cubetiqlabs/zro/pkg/control/service"
	"github.com/cubetiqlabs/zro/pkg/control/ws"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/gateway/balancer"
	"github.com/cubetiqlabs/zro/pkg/gateway/proxy"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server is the HTTP/REST Control Plane API server for ZRO.
type Server struct {
	cfg          *config.ControlPlaneConfig
	db           *store.DB
	svc          *service.Service
	httpServer   *http.Server
	mux          *http.ServeMux
	gatewayProxy *proxy.Engine
	popAddrMu    sync.Mutex // serializes PoP address allocation

	// High-performance Realtime Communication
	grpcServer *grpc.Server
	grpcCtrl   *controlgrpc.Server
	grpcLis    net.Listener

	// Tenant-scoped fan-out shared by SSE, WebSocket and gRPC streams
	bus    *controlevents.Bus
	cancel context.CancelFunc
}

// NewServer creates a new instance of the Control Plane API Server.
func NewServer(cfg *config.ControlPlaneConfig, db *store.DB) *Server {
	mux := http.NewServeMux()
	bus := controlevents.NewBus()
	svc := service.New(cfg, db, bus)

	s := &Server{
		cfg:      cfg,
		db:       db,
		svc:      svc,
		mux:      mux,
		bus:      bus,
		grpcCtrl: controlgrpc.NewServer(cfg, db, svc),
	}
	s.grpcCtrl.SetEventSource(bus, s.grpcStreamScope)
	s.grpcCtrl.SetAuthenticator(s.grpcAuthenticate)

	if cfg.EnableGateway {
		s.gatewayProxy = proxy.NewEngine()
	}

	s.registerRoutes()
	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	if err := s.validateSecrets(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Launch background watcher for Edge PoP health / heartbeat tracking
	go s.popWatchWorker(ctx)

	// Reap stale nodes, expired enrollment redemptions and old probe history
	go s.svc.Maintain(ctx, time.Minute, s.cfg.NodeTTL)

	// Start gRPC server in background if configured
	if s.cfg.GRPCListenAddr != "" {
		creds, err := s.grpcTransportCredentials()
		if err != nil {
			return err
		}
		lis, err := net.Listen("tcp", s.cfg.GRPCListenAddr)
		if err != nil {
			slog.Warn("Failed to bind gRPC listener (skipping gRPC server)", "addr", s.cfg.GRPCListenAddr, "error", err)
		} else {
			s.grpcLis = lis
			s.grpcServer = s.NewGRPCServer(grpc.Creds(creds))
			go func() {
				slog.Info("ZRO Control Plane gRPC server listening", "addr", s.cfg.GRPCListenAddr, "tls", s.cfg.GRPCTLSCert != "")
				_ = s.grpcServer.Serve(lis)
			}()
		}
	}

	s.httpServer = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	slog.Info("ZRO Control Plane starting", "listen_addr", s.cfg.ListenAddr, "public_url", s.cfg.PublicURL)
	return s.httpServer.ListenAndServe()
}

// grpcTransportCredentials builds the gRPC listener's transport security.
// Bearer tokens travel in metadata, so plaintext is only allowed when the
// operator opts in explicitly (for example behind a TLS-terminating proxy).
func (s *Server) grpcTransportCredentials() (credentials.TransportCredentials, error) {
	if s.cfg.GRPCTLSCert == "" && s.cfg.GRPCTLSKey == "" {
		if !s.cfg.GRPCInsecure {
			return nil, errors.New("grpc_listen_addr is set without grpc_tls_cert/grpc_tls_key; configure TLS or set grpc_insecure: true")
		}
		slog.Warn("gRPC is running WITHOUT TLS; node tokens are sent in clear text. Use only behind a TLS terminator")
		return insecure.NewCredentials(), nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.GRPCTLSCert, s.cfg.GRPCTLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading gRPC TLS key pair: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if s.cfg.GRPCTLSClientCA != "" {
		pem, err := os.ReadFile(s.cfg.GRPCTLSClientCA)
		if err != nil {
			return nil, fmt.Errorf("reading gRPC client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("grpc_tls_client_ca contains no valid certificates")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsCfg), nil
}

// NewGRPCServer builds the authenticated gRPC server around the control-plane
// service. Pass grpc.Creds to enable TLS; Start does so from configuration.
func (s *Server) NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {
	srv := grpc.NewServer(append([]grpc.ServerOption{
		grpc.UnaryInterceptor(s.grpcCtrl.UnaryInterceptor()),
		grpc.StreamInterceptor(s.grpcCtrl.StreamInterceptor()),
		grpc.MaxRecvMsgSize(1 << 20),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	}, opts...)...)
	v1.RegisterControlPlaneServiceServer(srv, s.grpcCtrl)
	return srv
}

// validateSecrets refuses to run with a missing or well-known signing secret
// when authentication is enforced, and warns in permissive mode.
func (s *Server) validateSecrets() error {
	weak := s.cfg.SecretKey == "" || s.cfg.SecretKey == crypto.DefaultSecretKey
	switch {
	case weak && s.cfg.RequireAuth:
		return errors.New("control_plane.secret_key is empty or the shipped default; set a unique secret before enabling require_auth")
	case weak:
		slog.Warn("control_plane.secret_key is empty or the shipped default; enrollment tokens are forgeable. Do not expose this plane")
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.grpcLis != nil {
		_ = s.grpcLis.Close()
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Handler returns the HTTP handler (useful for testing).
func (s *Server) Handler() http.Handler {
	return withRequestID(s.mux)
}

type contextKey string

const (
	tenantContextKey contextKey = "zro_tenant"
	nodeContextKey   contextKey = "zro_node"
	edgeContextKey   contextKey = "zro_edge"
)

// TenantFromContext returns the authenticated Tenant from the request context.
func TenantFromContext(ctx context.Context) *core.Tenant {
	if t := controlauth.TenantFromContext(ctx); t != nil {
		return t
	}
	if val := ctx.Value(tenantContextKey); val != nil {
		if t, ok := val.(*core.Tenant); ok {
			return t
		}
	}
	return nil
}

// NodeFromContext returns the authenticated node from the request context.
func NodeFromContext(ctx context.Context) *core.Node {
	if node := controlauth.NodeFromContext(ctx); node != nil {
		return node
	}
	if val := ctx.Value(nodeContextKey); val != nil {
		if node, ok := val.(*core.Node); ok {
			return node
		}
	}
	return nil
}

func withTenant(ctx context.Context, tenant *core.Tenant) context.Context {
	ctx = controlauth.WithSubject(ctx, &controlauth.Subject{Kind: controlauth.KindTenant, Tenant: tenant})
	return context.WithValue(ctx, tenantContextKey, tenant)
}

func withNode(ctx context.Context, node *core.Node) context.Context {
	ctx = controlauth.WithSubject(ctx, &controlauth.Subject{Kind: controlauth.KindNode, Node: node})
	return context.WithValue(ctx, nodeContextKey, node)
}

func withEdge(ctx context.Context) context.Context { return withEdgePoP(ctx, "") }

func withEdgePoP(ctx context.Context, popCode string) context.Context {
	ctx = controlauth.WithSubject(ctx, &controlauth.Subject{Kind: controlauth.KindEdge, PoPCode: popCode})
	return context.WithValue(ctx, edgeContextKey, true)
}

// devTenantSlug identifies the throwaway tenant used by unauthenticated development mode.
const devTenantSlug = "default-org"

// defaultTenant returns the tenant anonymous callers act as when require_auth
// is off. It is a dedicated dev tenant, created only on an empty database. It is
// never an arbitrary real tenant: once real tenants exist and no dev tenant does,
// it returns nil and anonymous requests are refused.
func (s *Server) defaultTenant(ctx context.Context) *core.Tenant {
	tenants, _ := s.db.Tenants.List(ctx)
	for i := range tenants {
		if tenants[i].Slug == devTenantSlug {
			return &tenants[i]
		}
	}
	if len(tenants) > 0 {
		return nil
	}

	key, _, err := controlauth.GenerateToken("zro_key_")
	if err != nil {
		key = uuid.NewString()
	}
	defaultTenant := &core.Tenant{
		ID:        uuid.New(),
		Name:      "Default Organization",
		Slug:      devTenantSlug,
		APIKey:    key,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = s.db.Tenants.Create(ctx, defaultTenant)
	slog.Warn("Created permissive-mode default tenant; enable control_plane.require_auth for production",
		"tenant_id", defaultTenant.ID)
	return defaultTenant
}

func (s *Server) tenantAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := controlauth.TenantKey(r)
		if apiKey != "" {
			tenant, err := s.db.Tenants.GetByAPIKey(r.Context(), apiKey)
			if err != nil || tenant == nil || !tenant.IsActive {
				apiError(w, "unauthorized: invalid or inactive API key", http.StatusUnauthorized)
				return
			}
			next(w, r.WithContext(withTenant(r.Context(), tenant)))
			return
		}

		// When no API key is provided:
		if s.cfg.RequireAuth {
			apiError(w, "unauthorized: API key required in Authorization or X-API-Key header", http.StatusUnauthorized)
			return
		}

		// Permissive / dev mode: bind to the dev tenant, never to a real one.
		tenant := s.defaultTenant(r.Context())
		if tenant == nil {
			apiError(w, "unauthorized: API key required (anonymous access is only available before any tenant exists)", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(withTenant(r.Context(), tenant)))
	}
}

// nodeAuthMiddleware authenticates node-facing endpoints. Every node receives a
// token at enrollment, so a valid node token is always required.
func (s *Server) nodeAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := controlauth.NodeToken(r)
		if token == "" {
			apiError(w, "unauthorized: node token required", http.StatusUnauthorized)
			return
		}
		node, err := s.db.Nodes.GetByTokenHash(r.Context(), controlauth.HashToken(token))
		if err != nil || node == nil || !node.IsActive {
			apiError(w, "unauthorized: invalid or inactive node token", http.StatusUnauthorized)
			return
		}
		s.svc.Touch(r.Context(), node)
		next(w, r.WithContext(withNode(r.Context(), node)))
	}
}

// authenticateStream resolves the principal of a streaming request (node
// token, tenant API key, or edge API key). On failure it returns the error
// message to send to the client.
func (s *Server) authenticateStream(r *http.Request) (context.Context, string) {
	ctx := r.Context()
	rawToken := controlauth.NodeToken(r)

	// Node tokens are deliberately prefixed so we do not hash tenant/edge
	// keys against the node table.
	if strings.HasPrefix(rawToken, "zro_node_") {
		node, err := s.db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(rawToken))
		if err != nil || node == nil || !node.IsActive {
			return nil, "unauthorized: invalid or inactive node token"
		}
		return withNode(ctx, node), ""
	}

	tenantKey := controlauth.TenantKey(r)
	if tenantKey != "" {
		tenant, err := s.db.Tenants.GetByAPIKey(ctx, tenantKey)
		if err == nil && tenant != nil && tenant.IsActive {
			return withTenant(ctx, tenant), ""
		}
		// The same header may carry an edge key; fall through to edge
		// authentication before rejecting it.
	}

	if edgeCtx, ok := s.authenticateEdge(r); ok && popCodeOf(edgeCtx) != "" {
		return edgeCtx, ""
	}

	if tenantKey != "" || rawToken != "" || controlauth.EdgeKey(r) != "" {
		return nil, "unauthorized: invalid stream credentials"
	}
	if s.cfg.RequireAuth {
		return nil, "unauthorized: stream credentials required"
	}
	tenant := s.defaultTenant(ctx)
	if tenant == nil {
		return nil, "unauthorized: stream credentials required"
	}
	return withTenant(ctx, tenant), ""
}

// streamAuthMiddleware authenticates streaming endpoints; handlers then apply
// the principal's event scope.
func (s *Server) streamAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, msg := s.authenticateStream(r)
		if msg != "" {
			apiError(w, msg, http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

// eventScope maps the authenticated principal to the events it may observe.
func (s *Server) eventScope(ctx context.Context) (controlevents.Scope, bool) {
	subject := controlauth.FromContext(ctx)
	if subject == nil {
		return controlevents.Scope{}, false
	}
	switch subject.Kind {
	case controlauth.KindEdge:
		return controlevents.Global(), true
	case controlauth.KindTenant:
		return controlevents.ForTenant(subject.Tenant.ID), true
	case controlauth.KindNode:
		network, err := s.db.Networks.GetByID(ctx, subject.Node.NetworkID)
		if err != nil || network == nil {
			return controlevents.Scope{}, false
		}
		return controlevents.ForNode(network.TenantID, network.ID), true
	}
	return controlevents.Scope{}, false
}

// grpcAuthenticate resolves gRPC metadata credentials with the same rules as
// the REST stream endpoints and returns a context carrying the principal.
func (s *Server) grpcAuthenticate(ctx context.Context) (context.Context, error) {
	header := http.Header{}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for k, vals := range md {
			for _, v := range vals {
				header.Add(k, v)
			}
		}
	}
	req := (&http.Request{Header: header, URL: &url.URL{}}).WithContext(ctx)
	// gRPC has no anonymous dev fallback (unlike the REST streams): no credentials, no access.
	if controlauth.NodeToken(req) == "" && controlauth.TenantKey(req) == "" && controlauth.EdgeKey(req) == "" {
		return ctx, status.Error(codes.Unauthenticated, "credentials required")
	}
	authCtx, msg := s.authenticateStream(req)
	if msg != "" {
		return ctx, status.Error(codes.Unauthenticated, msg)
	}
	return authCtx, nil
}

// grpcStreamScope maps the authenticated principal of a gRPC stream to its event scope.
func (s *Server) grpcStreamScope(ctx context.Context) (controlevents.Scope, error) {
	scope, ok := s.eventScope(ctx)
	if !ok {
		return controlevents.Scope{}, status.Error(codes.PermissionDenied, "no event scope for principal")
	}
	return scope, nil
}

const popKeyPrefix = "zro_pop_"

func (s *Server) isValidEdgeKey(r *http.Request) bool {
	key := controlauth.EdgeKey(r)
	expected := s.cfg.EdgeAPIKey
	if key == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(expected)) == 1
}

// popCodeOf returns the PoP an authenticated edge principal belongs to ("" for
// the shared registration key).
func popCodeOf(ctx context.Context) string {
	if sub := controlauth.FromContext(ctx); sub != nil && sub.Kind == controlauth.KindEdge {
		return sub.PoPCode
	}
	return ""
}

// authenticateEdge identifies an edge principal. A per-PoP credential
// identifies its PoP; the shared registration key identifies a registrar that
// may only claim PoPs.
func (s *Server) authenticateEdge(r *http.Request) (context.Context, bool) {
	key := controlauth.EdgeKey(r)
	if strings.HasPrefix(key, popKeyPrefix) {
		pop, err := s.db.EdgePoPs.GetByKeyHash(r.Context(), controlauth.HashToken(key))
		if err != nil || pop == nil {
			return nil, false
		}
		return withEdgePoP(r.Context(), pop.PoPCode), true
	}
	if s.isValidEdgeKey(r) {
		return withEdge(r.Context()), true
	}
	return nil, false
}

// edgeOpen reports the unauthenticated development mode for edge endpoints.
func (s *Server) edgeOpen() bool { return !s.cfg.RequireAuth && s.cfg.EdgeAPIKey == "" }

// edgeAuthMiddleware admits registrars (shared key) and PoPs (own credential).
func (s *Server) edgeAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if controlauth.EdgeKey(r) != "" {
			if ctx, ok := s.authenticateEdge(r); ok {
				next(w, r.WithContext(ctx))
				return
			}
			apiError(w, "unauthorized: invalid edge credential", http.StatusUnauthorized)
			return
		}
		if !s.edgeOpen() {
			apiError(w, "unauthorized: edge credential required", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(withEdge(r.Context())))
	}
}

// popAuthMiddleware admits only an edge presenting its own per-PoP credential.
func (s *Server) popAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.edgeAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if popCodeOf(r.Context()) == "" && !s.edgeOpen() {
			apiError(w, "forbidden: a per-PoP credential is required; re-register to obtain one", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// authorizeNetwork resolves a network and verifies that the current principal
// may observe or mutate it. Requests without a principal are denied.
func (s *Server) authorizeNetwork(ctx context.Context, networkID string) (*core.Network, bool) {
	network, err := s.db.Networks.GetByID(ctx, networkID)
	if err != nil || network == nil {
		return nil, false
	}

	subject := controlauth.FromContext(ctx)
	if subject == nil {
		return network, false
	}

	switch subject.Kind {
	case controlauth.KindNode:
		return network, subject.Node != nil && subject.Node.IsActive && subject.Node.NetworkID == network.ID
	case controlauth.KindTenant:
		return network, subject.Tenant != nil && subject.Tenant.IsActive && network.TenantID == subject.Tenant.ID
	case controlauth.KindEdge:
		return network, true
	default:
		return network, false
	}
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /healthz", s.handleLive)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /api/v1/openapi.yaml", s.handleOpenAPI)

	// Network Management (ZeroTier-styled 16-hex Network ID)
	s.mux.HandleFunc("GET /api/v1/networks/{id}", s.tenantAuthMiddleware(s.handleGetNetwork))
	s.mux.HandleFunc("GET /api/v1/nodes/{id}", s.tenantAuthMiddleware(s.handleGetNode))
	s.mux.HandleFunc("GET /api/v1/pops/{code}", s.handleGetPoP)
	s.mux.HandleFunc("GET /api/v1/tenants/{id}", s.adminAuthMiddleware(s.handleGetTenant))
	s.mux.HandleFunc("GET /api/v1/acl/rules/{id}", s.tenantAuthMiddleware(s.handleGetACLRule))
	s.mux.HandleFunc("PATCH /api/v1/networks/{id}", s.tenantAuthMiddleware(s.handleUpdateNetwork))
	s.mux.HandleFunc("DELETE /api/v1/networks/{id}", s.tenantAuthMiddleware(s.handleDeleteNetwork))
	s.mux.HandleFunc("GET /api/v1/nodes", s.tenantAuthMiddleware(s.handleListNodes))
	s.mux.HandleFunc("DELETE /api/v1/nodes/{id}", s.tenantAuthMiddleware(s.handleDeleteNode))
	s.mux.HandleFunc("DELETE /api/v1/pops/{code}", s.adminAuthMiddleware(s.handleDeletePoP))
	s.mux.HandleFunc("POST /api/v1/networks", s.tenantAuthMiddleware(s.handleCreateNetwork))
	s.mux.HandleFunc("GET /api/v1/networks", s.tenantAuthMiddleware(s.handleListNetworks))
	s.mux.HandleFunc("POST /api/v1/networks/{id}/tokens", s.tenantAuthMiddleware(s.handleCreateEnrollmentToken))

	// Tenant administration (bootstrap admin key; disabled when admin_api_key is empty)
	s.mux.HandleFunc("POST /api/v1/tenants", s.adminAuthMiddleware(s.handleCreateTenant))
	s.mux.HandleFunc("GET /api/v1/tenants", s.adminAuthMiddleware(s.handleListTenants))
	s.mux.HandleFunc("DELETE /api/v1/tenants/{id}", s.adminAuthMiddleware(s.handleDeleteTenant))
	s.mux.HandleFunc("POST /api/v1/tenants/{id}/rotate-key", s.adminAuthMiddleware(s.handleRotateTenantKey))

	// Edge PoPs, Dynamic Registration & Real-time Heartbeats
	s.mux.HandleFunc("GET /api/v1/pops", s.handleListPoPs)
	s.mux.HandleFunc("POST /api/v1/edge/register", s.edgeAuthMiddleware(s.handleRegisterEdgePoP))
	s.mux.HandleFunc("POST /api/v1/edge/heartbeat", s.popAuthMiddleware(s.handleEdgeHeartbeat))
	s.mux.HandleFunc("POST /api/v1/edge/deregister", s.popAuthMiddleware(s.handleEdgeDeregister))
	s.mux.HandleFunc("GET /api/v1/edge/sync", s.popAuthMiddleware(s.handleEdgeSync))
	s.mux.HandleFunc("POST /api/v1/pops/{code}/reset-key", s.adminAuthMiddleware(s.handleResetPoPKey))

	// Live Mesh Topology Graph (Real-Time)
	s.mux.HandleFunc("GET /api/v1/mesh/graph", s.tenantAuthMiddleware(s.handleGetMeshGraph))
	s.mux.HandleFunc("GET /api/v1/topology", s.tenantAuthMiddleware(s.handleGetMeshGraph))

	// Microsegmentation & Access Control (Zero-Trust ACLs)
	s.mux.HandleFunc("POST /api/v1/acl/rules", s.tenantAuthMiddleware(s.handleCreateACLRule))
	s.mux.HandleFunc("GET /api/v1/acl/rules", s.tenantAuthMiddleware(s.handleListACLRules))
	s.mux.HandleFunc("DELETE /api/v1/acl/rules/{id}", s.tenantAuthMiddleware(s.handleDeleteACLRule))

	// Node Enrollment & Mesh Coordination
	s.mux.HandleFunc("POST /api/v1/enroll", s.handleEnrollNode)
	s.mux.HandleFunc("POST /api/v1/probes", s.nodeAuthMiddleware(s.handleReportProbes))
	s.mux.HandleFunc("GET /api/v1/network/{id}/peers", s.nodeAuthMiddleware(s.handleGetPeers))
	s.mux.HandleFunc("POST /api/v1/p2p/discover", s.nodeAuthMiddleware(s.handleP2PDiscover))

	// Ingress & Tunneling
	s.mux.HandleFunc("GET /api/v1/acl/policy", s.nodeAuthMiddleware(s.handleACLPolicy))
	s.mux.HandleFunc("DELETE /api/v1/node", s.nodeAuthMiddleware(s.handleDeregister))
	s.mux.HandleFunc("POST /api/v1/tunnels", s.nodeAuthMiddleware(s.handleRegisterTunnel))
	s.mux.HandleFunc("GET /api/v1/tunnels", s.nodeAuthMiddleware(s.handleListTunnels))
	s.mux.HandleFunc("DELETE /api/v1/tunnels/{id}", s.nodeAuthMiddleware(s.handleDeleteTunnel))
	s.mux.HandleFunc("GET /api/v1/gateway/routes", s.nodeAuthMiddleware(s.handleGetGatewayRoutes))
	s.mux.HandleFunc("GET /api/v1/events", s.streamAuthMiddleware(s.handleEventStream))

	// Real-Time WebSockets Event Hub (RFC 6455)
	s.mux.HandleFunc("/api/v1/ws", s.streamAuthMiddleware(s.handleWebSocket))
	s.mux.HandleFunc("/ws/v1/events", s.streamAuthMiddleware(s.handleWebSocket))

	if s.cfg.EnableGateway {
		s.mux.HandleFunc("/", s.handleGatewayFallback)
	}
}

// handleOpenAPI serves the API description; it is public like the docs it feeds.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"service":   "zro-plane",
		"timestamp": time.Now(),
	})
}

// CreateNetworkRequest defines parameters for creating an overlay network.
type CreateNetworkRequest struct {
	Name      string `json:"name"`
	IPv4CIDR  string `json:"ipv4_cidr"`
	IPv6CIDR  string `json:"ipv6_cidr"`
	DNSDomain string `json:"dns_domain"`
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req CreateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.IPv4CIDR == "" {
		req.IPv4CIDR = s.cfg.DefaultCIDRv4
	}
	if req.IPv6CIDR == "" {
		req.IPv6CIDR = s.cfg.DefaultCIDRv6
	}
	if req.DNSDomain == "" {
		req.DNSDomain = "zro.internal"
	}
	if req.Name == "" {
		req.Name = "Mesh Network"
	}

	netID := core.GenerateNetworkID() // ZeroTier-style 16-hex character ID

	tenantID := TenantFromContext(r.Context()).ID // set by tenantAuthMiddleware

	network := &core.Network{
		ID:        netID,
		TenantID:  tenantID,
		Name:      req.Name,
		Slug:      req.Name,
		IPv4CIDR:  req.IPv4CIDR,
		IPv6CIDR:  req.IPv6CIDR,
		DNSDomain: req.DNSDomain,
		MTU:       1420,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.Networks.Create(r.Context(), network); err != nil {
		apiError(w, fmt.Sprintf("failed to create network: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Created new overlay network", "id", network.ID, "name", network.Name, "cidr", network.IPv4CIDR)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(network)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context()).ID // set by tenantAuthMiddleware

	networks, err := s.db.Networks.ListByTenantID(r.Context(), tenantID)
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writePage(w, r, networks)
}

func (s *Server) handleListPoPs(w http.ResponseWriter, r *http.Request) {
	var pops []core.EdgePoP
	var err error
	if r.URL.Query().Get("all") == "true" {
		pops, err = s.db.EdgePoPs.ListAll(r.Context())
	} else {
		pops, err = s.db.EdgePoPs.ListHealthy(r.Context())
	}
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pops)
}

// RegisterEdgePoPRequest defines dynamic registration payload from an Edge Data Plane node.
type RegisterEdgePoPRequest struct {
	PoPCode        string `json:"pop_code"` // e.g. "KH", "SG", "US", "HK", "DE"
	Region         string `json:"region"`
	PublicEndpoint string `json:"public_endpoint"` // e.g. "173.1.1.1:51820"
	PublicKey      string `json:"public_key"`      // Curve25519 public key
	Weight         int    `json:"weight"`
	IsAnycast      bool   `json:"is_anycast"`
}

var popCodeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$`)

func (s *Server) handleRegisterEdgePoP(w http.ResponseWriter, r *http.Request) {
	var req RegisterEdgePoPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !popCodeRE.MatchString(req.PoPCode) || req.PublicEndpoint == "" {
		apiError(w, "valid pop_code and public_endpoint are required", http.StatusBadRequest)
		return
	}
	if err := crypto.ValidatePublicKey(req.PublicKey); err != nil {
		apiError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Weight <= 0 {
		req.Weight = 100
	}

	existing, _ := s.db.EdgePoPs.GetByPoPCode(r.Context(), req.PoPCode)
	caller := popCodeOf(r.Context())

	// A claimed PoP can only be re-registered by its own credential, so a holder
	// of the shared key cannot overwrite another PoP's key and endpoint.
	if existing != nil && existing.KeyHash != "" && caller != existing.PoPCode {
		apiError(w, "pop is already claimed; present its credential or have an admin reset it", http.StatusForbidden)
		return
	}
	if caller != "" && (existing == nil || caller != req.PoPCode) {
		apiError(w, "credential does not belong to this pop", http.StatusForbidden)
		return
	}

	var popKey, keyHash string
	if existing == nil || existing.KeyHash == "" {
		var err error
		if popKey, keyHash, err = controlauth.GenerateToken(popKeyPrefix); err != nil {
			apiError(w, "failed to issue pop credential", http.StatusInternalServerError)
			return
		}
	}

	var pop core.EdgePoP
	if existing != nil {
		pop = *existing
		if err := s.assignPoPAddress(r.Context(), &pop); err != nil {
			apiError(w, "failed to assign PoP mesh address", http.StatusInternalServerError)
			return
		}
		if keyHash != "" {
			pop.KeyHash = keyHash
		}
		pop.PublicEndpoint = req.PublicEndpoint
		pop.PublicKey = req.PublicKey
		pop.Region = req.Region
		pop.Weight = req.Weight
		pop.IsHealthy = true
		pop.LastSeenAt = time.Now()
		pop.UpdatedAt = time.Now()
		if err := s.db.EdgePoPs.Update(r.Context(), &pop); err != nil {
			apiError(w, "failed to update PoP", http.StatusInternalServerError)
			return
		}
	} else {
		pop = core.EdgePoP{
			ID:             uuid.New(),
			PoPCode:        req.PoPCode,
			Region:         req.Region,
			PublicEndpoint: req.PublicEndpoint,
			PublicKey:      req.PublicKey,
			Weight:         req.Weight,
			IsAnycast:      req.IsAnycast,
			IsHealthy:      true,
			KeyHash:        keyHash,
			LastSeenAt:     time.Now(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		if err := s.assignPoPAddress(r.Context(), &pop); err != nil {
			apiError(w, "failed to assign PoP mesh address", http.StatusInternalServerError)
			return
		}
		if err := s.db.EdgePoPs.Create(r.Context(), &pop); err != nil {
			apiError(w, "failed to register PoP", http.StatusInternalServerError)
			return
		}
	}

	slog.Info("Edge Data Plane PoP registered dynamically", "pop_code", pop.PoPCode, "endpoint", pop.PublicEndpoint, "pubkey", pop.PublicKey)

	// Broadcast edge update
	s.broadcastDelta(controlevents.Scope{}, map[string]any{
		"event":    "edge_registered",
		"pop_code": pop.PoPCode,
		"endpoint": pop.PublicEndpoint,
	})
	s.broadcastDelta(controlevents.Scope{}, map[string]any{
		"event": "mesh_graph_updated",
	})

	writeJSON(w, http.StatusOK, struct {
		core.EdgePoP
		PopKey string `json:"pop_key,omitempty"` // issued once, when the PoP is claimed
	}{pop, popKey})
}

// handleResetPoPKey lets an admin release a claimed PoP (for example after the
// edge lost its state) so it can register again with the shared key.
func (s *Server) handleResetPoPKey(w http.ResponseWriter, r *http.Request) {
	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), r.PathValue("code"))
	if err != nil || pop == nil {
		apiError(w, "pop not found", http.StatusNotFound)
		return
	}
	pop.KeyHash = ""
	if err := s.db.EdgePoPs.Update(r.Context(), pop); err != nil {
		apiError(w, "failed to reset pop credential", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleEdgeDeregister marks the calling PoP offline immediately instead of
// waiting for the heartbeat timeout.
func (s *Server) handleEdgeDeregister(w http.ResponseWriter, r *http.Request) {
	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), popCodeOf(r.Context()))
	if err != nil || pop == nil {
		apiError(w, "pop not found", http.StatusNotFound)
		return
	}
	pop.IsHealthy = false
	pop.UpdatedAt = time.Now()
	if err := s.db.EdgePoPs.Update(r.Context(), pop); err != nil {
		apiError(w, "failed to update pop", http.StatusInternalServerError)
		return
	}
	s.broadcastDelta(controlevents.Scope{}, map[string]any{"event": "pop_status_changed", "pop_code": pop.PoPCode, "is_healthy": false, "status": "offline"})
	s.broadcastDelta(controlevents.Scope{}, map[string]any{"event": "mesh_graph_updated"})
	w.WriteHeader(http.StatusNoContent)
}

// EdgeHeartbeatRequest defines heartbeat telemetry sent by an Edge Data Plane node.
type EdgeHeartbeatRequest struct {
	PoPCode        string  `json:"pop_code"`
	Status         string  `json:"status"` // "online"
	PeersCount     int     `json:"peers_count"`
	ActiveTunnels  int     `json:"active_tunnels"`
	RTTMs          float64 `json:"rtt_ms"`
	PublicEndpoint string  `json:"public_endpoint"`
}

func (s *Server) handleEdgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req EdgeHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if caller := popCodeOf(r.Context()); caller != "" && caller != req.PoPCode {
		apiError(w, "credential does not belong to this pop", http.StatusForbidden)
		return
	}
	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), req.PoPCode)
	if err != nil || pop == nil {
		apiError(w, "pop not found", http.StatusNotFound)
		return
	}

	wasHealthy := pop.IsHealthy
	pop.IsHealthy = true
	pop.LastSeenAt = time.Now()
	pop.UpdatedAt = time.Now()
	if req.PublicEndpoint != "" {
		pop.PublicEndpoint = req.PublicEndpoint
	}
	_ = s.db.EdgePoPs.Update(r.Context(), pop)

	if !wasHealthy {
		slog.Info("Edge PoP recovered to healthy state via heartbeat", "pop_code", pop.PoPCode)
		s.broadcastDelta(controlevents.Scope{}, map[string]any{
			"event":      "pop_status_changed",
			"pop_code":   pop.PoPCode,
			"is_healthy": true,
			"status":     "online",
		})
		s.broadcastDelta(controlevents.Scope{}, map[string]any{
			"event": "mesh_graph_updated",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "acknowledged",
		"pop_code":  pop.PoPCode,
		"timestamp": time.Now(),
	})
}

func (s *Server) popWatchWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pops, err := s.db.EdgePoPs.ListAll(ctx)
			if err != nil {
				continue
			}

			for _, p := range pops {
				if p.IsHealthy && !p.LastSeenAt.IsZero() && time.Since(p.LastSeenAt) > 15*time.Second {
					p.IsHealthy = false
					p.UpdatedAt = time.Now()
					_ = s.db.EdgePoPs.Update(ctx, &p)
					slog.Warn("Edge PoP heartbeat timeout - marked degraded/offline", "pop_code", p.PoPCode, "last_seen", p.LastSeenAt)
					s.broadcastDelta(controlevents.Scope{}, map[string]any{
						"event":      "pop_status_changed",
						"pop_code":   p.PoPCode,
						"is_healthy": false,
						"status":     "offline",
					})
					s.broadcastDelta(controlevents.Scope{}, map[string]any{
						"event": "mesh_graph_updated",
					})
				}
			}
		}
	}
}

// assignPoPAddress gives pop a stable mesh address from the reserved block at
// the top of the default overlay CIDR. PoPs keep their address once set.
// ponytail: a process-local lock; replicas registering the same new PoP code at
// the same instant could pick one index; add a unique index if that matters.
func (s *Server) assignPoPAddress(ctx context.Context, pop *core.EdgePoP) error {
	if pop.OverlayIPv4 != "" {
		return nil
	}
	s.popAddrMu.Lock()
	defer s.popAddrMu.Unlock()
	pops, err := s.db.EdgePoPs.ListAll(ctx)
	if err != nil {
		return err
	}
	prefixes := core.OverlayPrefixes(s.cfg.DefaultCIDRv4, s.cfg.DefaultCIDRv6)
	used := make(map[string]bool, len(pops))
	for _, p := range pops {
		used[p.OverlayIPv4] = true
	}
	for i := 1; i <= ipam.PoPReserve; i++ {
		v4, err := ipam.PoPAddress(prefixes[0], i)
		if err != nil {
			return err
		}
		if used[v4] {
			continue
		}
		v6, err := ipam.DeriveIPv6(prefixes[1], v4)
		if err != nil {
			return err
		}
		pop.OverlayIPv4, pop.OverlayIPv6 = v4, v6
		return nil
	}
	return errors.New("no free PoP mesh address")
}

// EdgeSyncResponse is the mesh state returned to edge PoPs.
type EdgeSyncResponse = service.EdgeSnapshot

func (s *Server) handleEdgeSync(w http.ResponseWriter, r *http.Request) {
	pops, _ := s.db.EdgePoPs.ListHealthy(r.Context())
	var allNodes []core.Node

	// Edge PoPs are global infrastructure: synchronize nodes from every tenant
	// and network, not just the first tenant returned by the database.
	tenants, _ := s.db.Tenants.List(r.Context())
	for _, t := range tenants {
		nets, _ := s.db.Networks.ListByTenantID(r.Context(), t.ID)
		for _, n := range nets {
			nodes, _ := s.db.Nodes.ListByNetworkID(r.Context(), n.ID)
			allNodes = append(allNodes, nodes...)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EdgeSyncResponse{
		PoPs:  pops,
		Nodes: allNodes,
	})
}

// Wire types shared with clients; defined in the service layer.
type (
	EnrollRequest         = service.EnrollRequest
	EnrollResponse        = service.EnrollResponse
	P2PDiscoverRequest    = service.P2PDiscoverRequest
	P2PDiscoverResponse   = service.P2PDiscoverResponse
	GatewayBackendItem    = service.GatewayBackendItem
	GatewayRouteItem      = service.GatewayRouteItem
	GatewayRoutesResponse = service.GatewayRoutesResponse
)

// writeServiceError maps a service error to an HTTP status.
func writeServiceError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch service.KindOf(err) {
	case service.KindInvalid:
		code = http.StatusBadRequest
	case service.KindUnauthenticated:
		code = http.StatusUnauthorized
	case service.KindForbidden:
		code = http.StatusForbidden
	case service.KindNotFound:
		code = http.StatusNotFound
	case service.KindConflict, service.KindExhausted:
		code = http.StatusConflict
	}
	if code == http.StatusInternalServerError {
		slog.Error("control plane request failed", "error", err)
	}
	apiError(w, service.Message(err), code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnrollNode(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.CurrentToken = controlauth.NodeToken(r)
	resp, err := s.svc.Enroll(r.Context(), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleP2PDiscover(w http.ResponseWriter, r *http.Request) {
	var req P2PDiscoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	resp, err := s.svc.DiscoverP2P(r.Context(), NodeFromContext(r.Context()), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleReportProbes(w http.ResponseWriter, r *http.Request) {
	var sample core.LatencySample
	if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
		apiError(w, "invalid probe payload", http.StatusBadRequest)
		return
	}
	primary := s.svc.ReportProbe(r.Context(), NodeFromContext(r.Context()), sample)
	writeJSON(w, http.StatusAccepted, map[string]string{"primary_pop_code": primary})
}

func (s *Server) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	node := NodeFromContext(r.Context())
	if r.PathValue("id") != node.NetworkID {
		apiError(w, "forbidden: network access denied", http.StatusForbidden)
		return
	}
	peers, err := s.svc.Peers(r.Context(), node)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) handleRegisterTunnel(w http.ResponseWriter, r *http.Request) {
	var req core.Tunnel
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid tunnel payload", http.StatusBadRequest)
		return
	}
	tunnel, err := s.svc.RegisterTunnel(r.Context(), NodeFromContext(r.Context()), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if s.cfg.EnableGateway {
		_ = s.syncInternalGateway(r.Context())
	}
	writeJSON(w, http.StatusCreated, tunnel)
}

// handleACLPolicy returns the access rules the calling node enforces.
func (s *Server) handleACLPolicy(w http.ResponseWriter, r *http.Request) {
	rules, err := s.svc.ACLPolicy(r.Context(), NodeFromContext(r.Context()))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// handleDeregister removes the calling node from the mesh.
func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Deregister(r.Context(), NodeFromContext(r.Context())); err != nil {
		writeServiceError(w, err)
		return
	}
	if s.cfg.EnableGateway {
		_ = s.syncInternalGateway(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListTunnels returns the tunnels of the caller's network.
func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	tunnels, err := s.svc.ListTunnels(r.Context(), NodeFromContext(r.Context()))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tunnels)
}

// handleDeleteTunnel removes a tunnel owned by the calling node.
func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid tunnel id", http.StatusBadRequest)
		return
	}
	if err := s.svc.DeleteTunnel(r.Context(), NodeFromContext(r.Context()), id); err != nil {
		writeServiceError(w, err)
		return
	}
	if s.cfg.EnableGateway {
		_ = s.syncInternalGateway(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	scope, scoped := s.eventScope(r.Context())
	if !ok || !scoped {
		apiError(w, "streaming unavailable", http.StatusForbidden)
		return
	}

	// Long-lived stream: lift the server-wide write deadline.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sub := s.bus.Subscribe(scope)
	defer sub.Close()

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-sub.C:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, msg.Data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.eventScope(r.Context())
	if !ok {
		apiError(w, "streaming unavailable", http.StatusForbidden)
		return
	}
	ws.Serve(w, r, s.bus.Subscribe(scope), s.cfg.AllowedOrigins)
}

// broadcastDelta publishes a change event to the subscribers allowed to see
// scope. data["event"] names the event.
func (s *Server) broadcastDelta(scope controlevents.Scope, data map[string]any) {
	name, _ := data["event"].(string)
	if name == "" {
		name = "delta"
	}
	s.bus.Publish(scope, name, data)
}

// networkScope is the event scope of a known network.
func networkScope(n *core.Network) controlevents.Scope {
	return controlevents.Scope{TenantID: n.TenantID, NetworkID: n.ID}
}

// scopeForNetwork resolves the event scope of a network by ID. If the network
// cannot be loaded the event is scoped to the network ID only, so tenant
// subscribers never see it (fail closed).
func (s *Server) scopeForNetwork(ctx context.Context, networkID string) controlevents.Scope {
	if n, err := s.db.Networks.GetByID(ctx, networkID); err == nil && n != nil {
		return networkScope(n)
	}
	return controlevents.Scope{NetworkID: networkID}
}

func (s *Server) handleGetGatewayRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := s.svc.GatewayRoutes(r.Context(), NodeFromContext(r.Context()).NetworkID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, GatewayRoutesResponse{Routes: routes})
}

func (s *Server) syncInternalGateway(ctx context.Context) error {
	if s.gatewayProxy == nil {
		return nil
	}
	routes, err := s.svc.GatewayRoutes(ctx, "")
	if err != nil {
		return err
	}
	for _, r := range routes {
		var bList []*balancer.Backend
		for _, b := range r.Backends {
			bList = append(bList, &balancer.Backend{
				Address: b.Address,
				Weight:  b.Weight,
				Healthy: b.Healthy,
			})
		}
		bal := balancer.NewBalancer(balancer.StrategyLatency, bList)
		s.gatewayProxy.RegisterRoute(r.Hostname, bal)
	}
	return nil
}

func (s *Server) handleGatewayFallback(w http.ResponseWriter, r *http.Request) {
	if s.gatewayProxy != nil {
		s.gatewayProxy.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// MeshGraphNode represents a vertex in the real-time mesh topology graph.
type MeshGraphNode struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"` // "edge", "gateway", "peer"
	Hostname     string    `json:"hostname"`
	OverlayIPv4  string    `json:"overlay_ipv4,omitempty"`
	OverlayIPv6  string    `json:"overlay_ipv6,omitempty"`
	Endpoint     string    `json:"endpoint,omitempty"`
	PublicKey    string    `json:"public_key,omitempty"`
	Status       string    `json:"status"` // "online", "offline"
	AssignedPoP  string    `json:"assigned_pop,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	AllowedPorts []string  `json:"allowed_ports,omitempty"`
	DefaultDeny  bool      `json:"default_deny"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	Tunnels      []string  `json:"tunnels,omitempty"`
}

// MeshGraphEdge represents a directed connection/link in the mesh graph.
type MeshGraphEdge struct {
	ID      string  `json:"id"`
	Source  string  `json:"source"`
	Target  string  `json:"target"`
	Type    string  `json:"type"`   // "backbone_link", "edge_mesh", "p2p_direct", "gateway_proxy"
	Status  string  `json:"status"` // "active", "degraded", "idle"
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Details string  `json:"details,omitempty"`
}

// MeshGraphResponse returns the complete real-time topology of the mesh.
type MeshGraphResponse struct {
	NetworkID string          `json:"network_id"`
	Timestamp time.Time       `json:"timestamp"`
	Nodes     []MeshGraphNode `json:"nodes"`
	Edges     []MeshGraphEdge `json:"edges"`
	Stats     map[string]any  `json:"stats"`
}

func (s *Server) handleGetMeshGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	netID := r.URL.Query().Get("network_id")

	// The tenant middleware guarantees a tenant principal. Default to the
	// tenant's first network; an explicit network must belong to the tenant.
	if netID == "" {
		nets, _ := s.db.Networks.ListByTenantID(ctx, TenantFromContext(ctx).ID)
		if len(nets) > 0 {
			netID = nets[0].ID
		}
	} else if _, ok := s.authorizeNetwork(ctx, netID); !ok {
		apiError(w, "forbidden: network access denied", http.StatusForbidden)
		return
	}

	var graphNodes []MeshGraphNode
	var graphEdges []MeshGraphEdge

	// 1. Edge PoPs
	pops, _ := s.db.EdgePoPs.ListAll(ctx)
	for _, p := range pops {
		status := "offline"
		if p.IsHealthy && (p.LastSeenAt.IsZero() || time.Since(p.LastSeenAt) < 20*time.Second) {
			status = "online"
		}
		graphNodes = append(graphNodes, MeshGraphNode{
			ID:          "pop-" + p.PoPCode,
			Type:        "edge",
			Hostname:    "pop-" + p.PoPCode,
			Endpoint:    p.PublicEndpoint,
			PublicKey:   p.PublicKey,
			Status:      status,
			LastSeenAt:  p.LastSeenAt,
			AssignedPoP: p.PoPCode,
		})
	}

	// Connect Edge PoP backbones (inter-PoP mesh backbone links)
	for i := 0; i < len(pops); i++ {
		for j := i + 1; j < len(pops); j++ {
			graphEdges = append(graphEdges, MeshGraphEdge{
				ID:     fmt.Sprintf("backbone-%s-%s", pops[i].PoPCode, pops[j].PoPCode),
				Source: "pop-" + pops[i].PoPCode,
				Target: "pop-" + pops[j].PoPCode,
				Type:   "edge_mesh",
				Status: "active",
				RTTMs:  15.0,
			})
		}
	}

	// 2. Nodes in network
	var nodes []core.Node
	if netID != "" {
		nodes, _ = s.db.Nodes.ListByNetworkID(ctx, netID)
	}

	onlineCount := 0
	for _, n := range nodes {
		status := "offline"
		if time.Since(n.LastSeenAt) < 60*time.Second {
			status = "online"
			onlineCount++
		}

		tunnels, _ := s.db.Tunnels.ListByNodeID(ctx, n.ID)
		var tunNames []string
		for _, t := range tunnels {
			tunNames = append(tunNames, t.PublicHostname+" -> "+t.LocalAddress)
		}

		assignedCode := ""
		if n.AssignedPoP != nil {
			assignedCode = n.AssignedPoP.PoPCode
		} else if n.AssignedPoPID != nil {
			for _, p := range pops {
				if p.ID == *n.AssignedPoPID {
					assignedCode = p.PoPCode
					break
				}
			}
		}

		nodeTypeStr := string(n.NodeType)
		if nodeTypeStr == "" {
			nodeTypeStr = "peer"
		}

		graphNodes = append(graphNodes, MeshGraphNode{
			ID:           n.ID.String(),
			Type:         nodeTypeStr,
			Hostname:     n.Hostname,
			OverlayIPv4:  n.OverlayIPv4,
			OverlayIPv6:  n.OverlayIPv6,
			PublicKey:    n.PublicKey,
			Status:       status,
			AssignedPoP:  assignedCode,
			Tags:         []string(n.Tags),
			AllowedPorts: []string(n.AllowedPorts),
			DefaultDeny:  n.DefaultDeny,
			LastSeenAt:   n.LastSeenAt,
			Tunnels:      tunNames,
		})

		// Edge from node to its assigned Edge PoP
		if assignedCode != "" {
			graphEdges = append(graphEdges, MeshGraphEdge{
				ID:     fmt.Sprintf("link-%s-pop-%s", n.Hostname, assignedCode),
				Source: n.Hostname,
				Target: "pop-" + assignedCode,
				Type:   "backbone_link",
				Status: status,
				RTTMs:  5.0,
			})
		}

		// Gateway-to-node routes
		if len(tunnels) > 0 {
			for _, t := range tunnels {
				graphEdges = append(graphEdges, MeshGraphEdge{
					ID:      fmt.Sprintf("gw-route-%s-%s", t.PublicHostname, n.Hostname),
					Source:  "gateway",
					Target:  n.Hostname,
					Type:    "gateway_proxy",
					Status:  "active",
					Details: t.PublicHostname + " -> " + n.OverlayIPv4 + " (" + t.LocalAddress + ")",
				})
			}
		}
	}

	// 3. Add direct P2P edges between active peer nodes
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			n1 := nodes[i]
			n2 := nodes[j]
			if n1.NodeType == core.NodeTypePeer && n2.NodeType == core.NodeTypePeer {
				graphEdges = append(graphEdges, MeshGraphEdge{
					ID:     fmt.Sprintf("p2p-%s-%s", n1.Hostname, n2.Hostname),
					Source: n1.Hostname,
					Target: n2.Hostname,
					Type:   "p2p_direct",
					Status: "active",
					RTTMs:  12.0,
				})
			}
		}
	}

	resp := MeshGraphResponse{
		NetworkID: netID,
		Timestamp: time.Now(),
		Nodes:     graphNodes,
		Edges:     graphEdges,
		Stats: map[string]any{
			"total_nodes":  len(graphNodes),
			"online_nodes": onlineCount,
			"total_edges":  len(graphEdges),
			"edge_pops":    len(pops),
			"network_id":   netID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CreateACLRuleRequest defines parameters for a new microsegmentation rule.
type CreateACLRuleRequest struct {
	NetworkID string         `json:"network_id"`
	Priority  int            `json:"priority"`
	SourceIP  string         `json:"source_ip"`
	DestIP    string         `json:"dest_ip"`
	SourceTag string         `json:"source_tag"`
	DestTag   string         `json:"dest_tag"`
	Protocol  string         `json:"protocol"`
	Ports     string         `json:"ports"`
	Action    core.ACLAction `json:"action"`
}

func (s *Server) handleCreateACLRule(w http.ResponseWriter, r *http.Request) {
	var req CreateACLRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.NetworkID == "" {
		apiError(w, "network_id is required", http.StatusBadRequest)
		return
	}

	tenant := TenantFromContext(r.Context())
	if tenant != nil {
		net, err := s.db.Networks.GetByID(r.Context(), req.NetworkID)
		if err != nil || net == nil {
			apiError(w, "network not found", http.StatusNotFound)
			return
		}
		if net.TenantID != tenant.ID {
			apiError(w, "forbidden: network does not belong to tenant", http.StatusForbidden)
			return
		}
	}

	if req.Priority <= 0 {
		req.Priority = 100
	}
	if req.Action == "" {
		req.Action = core.ACLActionAllow
	}
	if req.Protocol == "" {
		req.Protocol = "*"
	}
	if req.Ports == "" {
		req.Ports = "*"
	}
	if req.SourceIP == "" {
		req.SourceIP = "*"
	}
	if req.DestIP == "" {
		req.DestIP = "*"
	}
	if req.SourceTag == "" {
		req.SourceTag = "*"
	}
	if req.DestTag == "" {
		req.DestTag = "*"
	}

	rule := &core.ACLRule{
		ID:        uuid.New(),
		NetworkID: req.NetworkID,
		Priority:  req.Priority,
		SourceIP:  req.SourceIP,
		DestIP:    req.DestIP,
		SourceTag: req.SourceTag,
		DestTag:   req.DestTag,
		Protocol:  req.Protocol,
		Ports:     req.Ports,
		Action:    req.Action,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := controlacl.ValidateRule(rule); err != nil {
		apiError(w, "invalid ACL rule: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.db.ACLs.Create(r.Context(), rule); err != nil {
		apiError(w, fmt.Sprintf("failed to create ACL rule: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Created new ACL rule", "id", rule.ID, "network_id", rule.NetworkID, "action", rule.Action, "ports", rule.Ports)

	// Broadcast ACL and graph update
	s.broadcastDelta(s.scopeForNetwork(r.Context(), rule.NetworkID), map[string]any{
		"event":      "acl_rules_updated",
		"network_id": rule.NetworkID,
		"rule_id":    rule.ID,
	})
	s.broadcastDelta(s.scopeForNetwork(r.Context(), rule.NetworkID), map[string]any{
		"event": "mesh_graph_updated",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rule)
}

func (s *Server) handleListACLRules(w http.ResponseWriter, r *http.Request) {
	netID := r.URL.Query().Get("network_id")
	if netID == "" {
		apiError(w, "network_id query parameter is required", http.StatusBadRequest)
		return
	}

	tenant := TenantFromContext(r.Context())
	if tenant != nil {
		net, err := s.db.Networks.GetByID(r.Context(), netID)
		if err != nil || net == nil {
			apiError(w, "network not found", http.StatusNotFound)
			return
		}
		if net.TenantID != tenant.ID {
			apiError(w, "forbidden: network does not belong to tenant", http.StatusForbidden)
			return
		}
	}

	rules, err := s.db.ACLs.ListByNetworkID(r.Context(), netID)
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writePage(w, r, rules)
}

func (s *Server) handleDeleteACLRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		apiError(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	rule, err := s.db.ACLs.GetByID(r.Context(), id)
	if err != nil || rule == nil {
		apiError(w, "rule not found", http.StatusNotFound)
		return
	}
	network, ok := s.authorizeNetwork(r.Context(), rule.NetworkID)
	if !ok {
		// Same response as a missing rule so rule IDs cannot be probed across tenants.
		apiError(w, "rule not found", http.StatusNotFound)
		return
	}

	if err := s.db.ACLs.Delete(r.Context(), id); err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scope := networkScope(network)
	s.broadcastDelta(scope, map[string]any{
		"event":      "acl_rules_updated",
		"network_id": rule.NetworkID,
		"rule_id":    idStr,
	})
	s.broadcastDelta(scope, map[string]any{
		"event":      "mesh_graph_updated",
		"network_id": rule.NetworkID,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// adminAuthMiddleware guards tenant administration with the bootstrap admin key.
func (s *Server) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := s.cfg.AdminAPIKey
		if expected == "" {
			apiError(w, "tenant administration is disabled; set control_plane.admin_api_key", http.StatusForbidden)
			return
		}
		key := controlauth.BearerToken(r)
		if key == "" {
			key = strings.TrimSpace(r.Header.Get("X-Admin-Key"))
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(expected)) != 1 {
			apiError(w, "unauthorized: invalid admin key", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type tenantResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	APIKey    string    `json:"api_key,omitempty"` // plaintext, only on create and rotate
}

func toTenantResponse(t *core.Tenant, withKey bool) tenantResponse {
	resp := tenantResponse{ID: t.ID, Name: t.Name, Slug: t.Slug, IsActive: t.IsActive, CreatedAt: t.CreatedAt}
	if withKey {
		resp.APIKey = t.APIKey
	}
	return resp
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,98}[a-z0-9]$`)

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || !slugRE.MatchString(req.Slug) {
		apiError(w, "name and a lower-case slug are required", http.StatusBadRequest)
		return
	}
	key, _, err := controlauth.GenerateToken("zro_key_")
	if err != nil {
		apiError(w, "failed to generate API key", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	tenant := &core.Tenant{ID: uuid.New(), Name: req.Name, Slug: req.Slug, APIKey: key, IsActive: true, CreatedAt: now, UpdatedAt: now}
	if err := s.db.Tenants.Create(r.Context(), tenant); err != nil {
		apiError(w, "failed to create tenant (slug may be taken)", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toTenantResponse(tenant, true))
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.db.Tenants.List(r.Context())
	if err != nil {
		apiError(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}
	out := make([]tenantResponse, 0, len(tenants))
	for i := range tenants {
		out = append(out, toTenantResponse(&tenants[i], false))
	}
	writePage(w, r, out)
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	nets, err := s.db.Networks.ListByTenantID(r.Context(), id)
	if err != nil {
		apiError(w, "failed to check tenant networks", http.StatusInternalServerError)
		return
	}
	if len(nets) > 0 {
		apiError(w, "tenant still owns networks; delete them first", http.StatusConflict)
		return
	}
	if err := s.db.Tenants.Delete(r.Context(), id); err != nil {
		apiError(w, "failed to delete tenant", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateTenantKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	key, _, err := controlauth.GenerateToken("zro_key_")
	if err != nil {
		apiError(w, "failed to generate API key", http.StatusInternalServerError)
		return
	}
	if err := s.db.Tenants.RotateAPIKey(r.Context(), id, key); err != nil {
		apiError(w, "tenant not found", http.StatusNotFound)
		return
	}
	tenant, err := s.db.Tenants.GetByID(r.Context(), id)
	if err != nil {
		apiError(w, "tenant not found", http.StatusNotFound)
		return
	}
	tenant.APIKey = key
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTenantResponse(tenant, true))
}
