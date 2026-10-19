package stun

import (
	"net"
	"testing"
	"time"
)

func TestSTUNRoundtrip(t *testing.T) {
	// 1. Start test STUN server
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	// Server loop in goroutine
	go func() {
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = ServeSTUN(serverConn, buf[:n], clientAddr)
		}
	}()

	// 2. Client discovers reflexive endpoint
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create client UDP: %v", err)
	}
	defer clientConn.Close()

	discovered, err := DiscoverPublicEndpoint(clientConn, serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("STUN discovery failed: %v", err)
	}

	clientLocalPort := clientConn.LocalAddr().(*net.UDPAddr).Port
	if discovered.Port != clientLocalPort {
		t.Fatalf("expected discovered port %d, got %d", clientLocalPort, discovered.Port)
	}

	if !discovered.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected discovered IP 127.0.0.1, got %v", discovered.IP)
	}
}
