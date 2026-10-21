package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
	"github.com/cubis/zro/pkg/node"
)

// TestIngressReachesLocalServiceOverWireGuard is the whole ingress path in one
// process: HTTP request -> gateway reverse proxy -> userspace overlay stack ->
// WireGuard (loopback UDP) -> node overlay listener -> loopback-only service.
func TestIngressReachesLocalServiceOverWireGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A service that only listens on loopback of the node's host.
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "hello from the node's local service")
	}))
	defer svc.Close()
	svcAddr := svc.Listener.Addr().String()
	_, portStr, _ := net.SplitHostPort(svcAddr)

	n, err := node.NewDaemon(&config.NodeConfig{Hostname: "svc", InterfaceName: "zro-ing-n", InterfaceMode: "netstack", MTU: 1420, DefaultDeny: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop()
	gw, err := NewDaemon(&config.GatewayConfig{Hostname: "gw", InterfaceName: "zro-ing-g", InterfaceMode: "netstack", MTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Stop()

	if err := n.AssignOverlay("100.64.0.30", ""); err != nil {
		t.Fatal(err)
	}
	if err := gw.dev.Configure("100.64.0.31", ""); err != nil {
		t.Fatal(err)
	}
	gwPort := gw.udpConn.LocalAddr().(*net.UDPAddr).Port
	// The responder (gateway) first, then the initiator (node), then wait for the session.
	if err := gw.wgManager.ApplyPeer(wireguard.PeerConfig{
		PublicKey:  n.PublicKey(),
		Endpoint:   fmt.Sprintf("127.0.0.1:%d", n.UDPPort()),
		AllowedIPs: []string{"100.64.0.30/32"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.AddDirectPeer(core.Node{PublicKey: gw.PublicKey(), OverlayIPv4: "100.64.0.31"}, fmt.Sprintf("127.0.0.1:%d", gwPort), true); err != nil {
		t.Fatal(err)
	}
	for i := 0; !n.PeerHandshaken(gw.PublicKey()); i++ {
		if i > 300 {
			t.Fatal("WireGuard handshake never completed")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := n.ExposeTunnel(ctx, svcAddr); err != nil {
		t.Fatal(err)
	}

	// Route the public hostname to the node's overlay address, as the plane would.
	gw.applyRoutes([]server.GatewayRouteItem{{
		Hostname: "app.example.com", Protocol: "http",
		Backends: []server.GatewayBackendItem{{Address: net.JoinHostPort("100.64.0.30", portStr), Weight: 100, Healthy: true}},
	}})

	front := httptest.NewServer(gw.ProxyEngine())
	defer front.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL, nil)
	req.Host = "app.example.com"

	var body string
	for attempt := 0; attempt < 10; attempt++ { // the first packets trigger the WireGuard handshake
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if body != "hello from the node's local service" {
		t.Fatalf("ingress did not reach the node's local service, got %q", body)
	}
}
