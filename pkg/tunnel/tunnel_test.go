package tunnel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestTunnelLocalServiceExposure(t *testing.T) {
	// 1. Local backend server
	localBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "internal-service-data")
	}))
	defer localBackend.Close()

	// Strip "http://"
	localAddr := localBackend.Listener.Addr().String()

	// 2. Client exposes the service
	client := NewClient()
	err := client.ExposeService(IngressDefinition{
		ID:             uuid.New(),
		NodeID:         uuid.New(),
		Name:           "api-service",
		LocalAddress:   localAddr,
		PublicHostname: "api.cubis.internal",
		Protocol:       "http",
	})
	if err != nil {
		t.Fatalf("failed to expose service: %v", err)
	}

	// 3. Request arrives for that hostname
	req := httptest.NewRequest("GET", "http://api.cubis.internal/test", nil)
	rec := httptest.NewRecorder()
	client.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK || string(respBody) != "internal-service-data" {
		t.Fatalf("tunnel failed: code=%d, body=%s", rec.Code, string(respBody))
	}

	// 4. Request for unexposed hostname should return 404
	unregisteredReq := httptest.NewRequest("GET", "http://unknown.domain.com/", nil)
	unregisteredRec := httptest.NewRecorder()
	client.ServeHTTP(unregisteredRec, unregisteredReq)
	if unregisteredRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown hostname, got %d", unregisteredRec.Code)
	}

	// 5. Test IngressRouter
	router := NewIngressRouter()
	router.Register("api.cubis.internal", "100.64.0.10:8080")
	target, found := router.Lookup("api.cubis.internal")
	if !found || target != "100.64.0.10:8080" {
		t.Fatalf("ingress router lookup failed: target=%s, found=%v", target, found)
	}
}
