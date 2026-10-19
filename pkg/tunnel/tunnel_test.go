package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTunnelLocalServiceExposure(t *testing.T) {
	// 1. Local backend server
	localBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "internal-service-data")
	}))
	defer localBackend.Close()

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

func TestSOCKS5TunnelRoundtrip(t *testing.T) {
	// 1. Start target TCP echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind echo server: %v", err)
	}
	defer targetListener.Close()

	go func() {
		for {
			c, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Start SOCKS5 Server
	socksServer := NewSOCKS5Server(nil)
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind socks5 listener: %v", err)
	}
	defer socksServer.Close()
	socksAddr := socksListener.Addr().String()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go socksServer.handleClient(conn)
		}
	}()

	// 3. Client connects to target TCP through SOCKS5 tunnel
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := SOCKS5DialContext(ctx, socksAddr, targetListener.Addr().String())
	if err != nil {
		t.Fatalf("SOCKS5DialContext failed: %v", err)
	}
	defer conn.Close()

	// 4. Send and verify echo
	msg := []byte("DATA_THROUGH_ZRO_SOCKS5_TUNNEL")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("failed to write through SOCKS5: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read through SOCKS5: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Fatalf("socks5 echo mismatch: expected %s, got %s", msg, buf)
	}
}

func TestUDPTunnelRoundtrip(t *testing.T) {
	// 1. Start target UDP echo server
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind UDP target: %v", err)
	}
	defer targetConn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := targetConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = targetConn.WriteToUDP(buf[:n], from)
		}
	}()

	// 2. Start UDP tunnel pointing to target
	tunnel, err := NewUDPTunnel("127.0.0.1:0", targetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("NewUDPTunnel failed: %v", err)
	}
	defer tunnel.Close()

	// 3. Client sends to UDP tunnel listener
	clientConn, err := net.Dial("udp", tunnel.localConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial UDP tunnel: %v", err)
	}
	defer clientConn.Close()

	payload := []byte("UDP_PAYLOAD_THROUGH_ZRO_TUNNEL")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("failed to send UDP through tunnel: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1024)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to receive UDP response through tunnel: %v", err)
	}

	if !bytes.Equal(respBuf[:n], payload) {
		t.Fatalf("UDP tunnel echo mismatch: expected %s, got %s", payload, respBuf[:n])
	}
}
