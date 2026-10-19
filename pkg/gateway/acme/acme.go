package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// Config configures automated ACME TLS certificate lifecycle.
type Config struct {
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"`
	CertDir string   `json:"cert_dir"`
	Email   string   `json:"email"`
}

// Manager wraps autocert.Manager for production ACME certificate provisioning.
type Manager struct {
	cfg     Config
	manager *autocert.Manager
}

// NewManager creates a new ACME TLS manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CertDir == "" {
		cfg.CertDir = "/var/lib/zro/certs"
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create ACME cert directory %s: %w", cfg.CertDir, err)
	}

	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cfg.CertDir),
	}

	if cfg.Email != "" {
		m.Email = cfg.Email
	}

	// If explicit domains configured, restrict host policy
	if len(cfg.Domains) > 0 {
		m.HostPolicy = func(ctx context.Context, host string) error {
			// Strip port if present
			h := host
			if idx := strings.IndexByte(host, ':'); idx != -1 {
				h = host[:idx]
			}
			for _, d := range cfg.Domains {
				if strings.EqualFold(d, h) || strings.HasSuffix(h, "."+d) {
					return nil
				}
			}
			return fmt.Errorf("acme: host %q not permitted by policy", host)
		}
	}

	return &Manager{
		cfg:     cfg,
		manager: m,
	}, nil
}

// TLSConfig returns a tls.Config configured for automated ACME handshakes.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := m.manager.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// HTTPHandler returns an HTTP handler that intercepts ACME HTTP-01 challenges on port 80
// and forwards other traffic to the fallback handler or redirects to HTTPS.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.manager.HTTPHandler(fallback)
}

// LocalCertFile returns paths to cached certificate files if they exist.
func (m *Manager) LocalCertFile(domain string) (certFile, keyFile string) {
	certFile = filepath.Join(m.cfg.CertDir, domain+".crt")
	keyFile = filepath.Join(m.cfg.CertDir, domain+".key")
	return certFile, keyFile
}
