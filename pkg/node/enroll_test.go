package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/crypto"
)

func enrollDaemon(url string, c *http.Client) *Daemon {
	return &Daemon{cfg: &config.NodeConfig{PlaneEndpoint: url, Hostname: "n"}, keyPair: &crypto.KeyPair{PublicKey: "k"}, httpClient: c}
}

func TestEnrollRetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(server.EnrollResponse{NetworkID: "net"})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := enrollDaemon(srv.URL, srv.Client()).enrollWithRetry(ctx, nil, nil)
	if err != nil || resp.NetworkID != "net" || calls.Load() != 2 {
		t.Fatalf("resp=%+v err=%v calls=%d", resp, err, calls.Load())
	}
}

func TestEnrollDoesNotRetryRejection(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "token expired", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := enrollDaemon(srv.URL, srv.Client()).enrollWithRetry(context.Background(), nil, nil)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}
