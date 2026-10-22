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
	socksServer := NewSOCKS5Server((&net.Dialer{}).DialContext)
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

	conn := socksConnect(ctx, t, socksAddr, targetListener.Addr().String())
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

// socksConnect performs an RFC 1928 no-auth CONNECT to an IPv4 target.
func socksConnect(ctx context.Context, t *testing.T, socksAddr, target string) net.Conn {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks server: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil || greeting[1] != 0x00 {
		t.Fatalf("socks greeting failed: %v %x", err, greeting)
	}

	host, portStr, _ := net.SplitHostPort(target)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	_, _ = conn.Write(req)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("socks connect failed: %v %x", err, reply)
	}
	return conn
}
