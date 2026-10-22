package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/config"
)

func TestHeartbeatRejectionTriggersReregister(t *testing.T) {
	for status, want := range map[int]bool{200: true, 503: true, 401: false, 404: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		e := &PoPDaemon{cfg: &config.EdgeConfig{PlaneEndpoint: srv.URL, PoPCode: "T"}, httpClient: srv.Client()}
		if got := e.sendHeartbeat(context.Background()); got != want {
			t.Errorf("status %d: registered=%v want %v", status, got, want)
		}
		srv.Close()
	}
}
