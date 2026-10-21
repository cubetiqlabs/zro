package puncher

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestPunchSuccess(t *testing.T) {
	ctx := context.Background()

	// 1. Local initiator socket
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP for initiator: %v", err)
	}
	defer localConn.Close()

	// 2. Remote peer socket
	remoteConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP for remote peer: %v", err)
	}
	defer remoteConn.Close()

	// Remote responder loop: upon receiving MagicPing, replies with MagicPong
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := remoteConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], MagicPing) {
				_, _ = remoteConn.WriteToUDP(MagicPong, from)
			}
		}
	}()

	res, err := Punch(ctx, localConn, remoteConn.LocalAddr().String(), 1*time.Second)
	if err != nil {
		t.Fatalf("Punch failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Punch to succeed")
	}
	if res.RTT <= 0 {
		t.Fatalf("expected positive RTT, got %v", res.RTT)
	}
}

func TestPunchTimeout(t *testing.T) {
	ctx := context.Background()

	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer localConn.Close()

	// Silent socket that never responds
	dummyConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	dummyAddr := dummyConn.LocalAddr().String()
	_ = dummyConn.Close() // closed immediately, nothing responds

	res, err := Punch(ctx, localConn, dummyAddr, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("expected nil error on timeout, got %v", err)
	}
	if res.Success {
		t.Fatalf("expected punch failure on non-responding endpoint")
	}
}

func TestPunchContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	localConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer localConn.Close()

	_, err := Punch(ctx, localConn, "127.0.0.1:51820", 1*time.Second)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestPunchInvalidEndpoint(t *testing.T) {
	localConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer localConn.Close()

	_, err := Punch(context.Background(), localConn, "invalid-endpoint-addr:port:abc", 500*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error resolving invalid endpoint")
	}
}
