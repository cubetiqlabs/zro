package derp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/crypto"
)

func TestDERPRelayRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Start DERP Relay Server on random TCP port
	serverKP, _ := crypto.GenerateKeyPair()
	srv, err := NewServer(serverKP)
	if err != nil {
		t.Fatalf("failed to create DERP server: %v", err)
	}
	defer srv.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	serverAddr := l.Addr().String()

	go func() {
		_ = srv.Serve(l)
	}()

	// 2. Connect Client A
	kpA, _ := crypto.GenerateKeyPair()
	clientA, err := ConnectDERP(ctx, serverAddr, kpA)
	if err != nil {
		t.Fatalf("client A failed to connect: %v", err)
	}
	defer clientA.Close()

	// 3. Connect Client B
	kpB, _ := crypto.GenerateKeyPair()
	clientB, err := ConnectDERP(ctx, serverAddr, kpB)
	if err != nil {
		t.Fatalf("client B failed to connect: %v", err)
	}
	defer clientB.Close()

	time.Sleep(50 * time.Millisecond)

	// 4. Client A sends encapsulated packet to Client B
	keyB, err := parseKey(kpB.PublicKey)
	if err != nil {
		t.Fatalf("failed to parse key B: %v", err)
	}

	testPayload := []byte("REAL_WIREGUARD_PACKET_CONTENT_FOR_PEER_B")
	if err := clientA.Send(keyB, testPayload); err != nil {
		t.Fatalf("client A failed to send packet: %v", err)
	}

	// 5. Client B receives relayed packet
	select {
	case pkt, ok := <-clientB.Recv():
		if !ok {
			t.Fatalf("client B recv channel closed prematurely")
		}
		if !bytes.Equal(pkt.Payload, testPayload) {
			t.Fatalf("payload mismatch: expected %q, got %q", testPayload, pkt.Payload)
		}

		keyA, _ := parseKey(kpA.PublicKey)
		if pkt.SrcPubKey != keyA {
			t.Fatalf("source public key mismatch: expected %x, got %x", keyA, pkt.SrcPubKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for relayed DERP packet on Client B")
	}
}
