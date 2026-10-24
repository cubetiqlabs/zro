package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestPlaneTransportRetriesReset(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 { // first request: drop the connection like a CDN would
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := &http.Client{Transport: newPlaneTransport()}
	resp, err := c.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}
