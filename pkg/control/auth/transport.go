package auth

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// bearerTransport adds an Authorization header to requests for one host only,
// so the credential can never leak to another origin.
type bearerTransport struct {
	base  http.RoundTripper
	host  string
	token func() string
}

// NewBearerTransport returns a RoundTripper that sends "Authorization: Bearer
// <token()>" on requests to planeURL's host while token() is non-empty.
func NewBearerTransport(base http.RoundTripper, planeURL string, token func() string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	u, _ := url.Parse(strings.TrimSpace(planeURL))
	host := ""
	if u != nil {
		host = u.Host
	}
	return &bearerTransport{base: base, host: host, token: token}
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tok := t.token(); tok != "" && req.URL.Host == t.host && req.Header.Get("Authorization") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return t.base.RoundTrip(req)
}

// TokenHolder is a concurrency-safe slot for the bearer token a client
// receives at enrollment.
type TokenHolder struct{ v atomic.Value }

// Set stores the token.
func (h *TokenHolder) Set(token string) { h.v.Store(token) }

// Get returns the token, or "" before enrollment.
func (h *TokenHolder) Get() string { t, _ := h.v.Load().(string); return t }
