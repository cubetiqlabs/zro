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

func startServer(t *testing.T, mutate func(*Server)) (*Server, string) {
	t.Helper()
	kp, _ := crypto.GenerateKeyPair()
	srv, err := NewServer(kp)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(srv)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, l.Addr().String()
}

func TestHandshakeRejectsKeyImpersonation(t *testing.T) {
	_, addr := startServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	victim, _ := crypto.GenerateKeyPair()
	attacker, _ := crypto.GenerateKeyPair()
	vc, err := ConnectDERP(ctx, addr, victim)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()

	// The attacker claims the victim's public key but only holds its own private key.
	forged := &crypto.KeyPair{PublicKey: victim.PublicKey, PrivateKey: attacker.PrivateKey}
	ac, err := ConnectDERP(ctx, addr, forged)
	if err == nil {
		// The server drops the connection after the failed proof; the client
		// notices on its first read.
		select {
		case <-ac.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("a client that cannot prove its key must be disconnected")
		}
		ac.Close()
	}

	// The victim's session must be untouched and still reachable.
	peer, _ := crypto.GenerateKeyPair()
	pc, err := ConnectDERP(ctx, addr, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	victimKey, _ := parseKey(victim.PublicKey)
	time.Sleep(50 * time.Millisecond)
	if err := pc.Send(victimKey, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-vc.Recv():
		if string(pkt.Payload) != "hello" {
			t.Fatalf("unexpected payload %q", pkt.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the victim's session was hijacked or dropped")
	}
}

func TestAuthorizeHookGatesTheRelay(t *testing.T) {
	allowed, _ := crypto.GenerateKeyPair()
	denied, _ := crypto.GenerateKeyPair()
	allowedKey, _ := parseKey(allowed.PublicKey)
	_, addr := startServer(t, func(s *Server) { s.Authorize = func(k [KeyLen]byte) bool { return k == allowedKey } })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := ConnectDERP(ctx, addr, allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()

	no, err := ConnectDERP(ctx, addr, denied)
	if err == nil {
		defer no.Close()
		select {
		case <-no.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("an unauthorized key must be disconnected")
		}
	}
}

func TestServerLocalEndpointRoundtrip(t *testing.T) {
	srv, addr := startServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kp, _ := crypto.GenerateKeyPair()
	c, err := ConnectDERP(ctx, addr, kp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond)

	// client -> server's own key
	if err := c.Send(srv.pubKey, []byte("to-pop")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-srv.Local().Recv():
		clientKey, _ := parseKey(kp.PublicKey)
		if string(pkt.Payload) != "to-pop" || pkt.SrcPubKey != clientKey {
			t.Fatalf("unexpected local packet %+v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet addressed to the PoP never reached its local endpoint")
	}

	// server -> client
	clientKey, _ := parseKey(kp.PublicKey)
	if err := srv.Local().Send(clientKey, []byte("from-pop")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-c.Recv():
		if string(pkt.Payload) != "from-pop" || pkt.SrcPubKey != srv.pubKey {
			t.Fatalf("unexpected packet %+v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PoP reply never arrived")
	}
	if err := srv.Local().Send([32]byte{9}, []byte("x")); err != ErrClientNotFound {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
}

func TestConnectionCapsRejectExtraClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, addr := startServer(t, func(s *Server) { s.Limits.MaxConnsPerIP = 1 })

	kp1, _ := crypto.GenerateKeyPair()
	c1, err := ConnectDERP(ctx, addr, kp1)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	kp2, _ := crypto.GenerateKeyPair()
	if c2, err := ConnectDERP(ctx, addr, kp2); err == nil {
		c2.Close()
		t.Fatal("a second connection from the same IP must be refused")
	}
}

func TestSessionRateLimitDropsExcessPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv, addr := startServer(t, func(s *Server) { s.Limits.PacketsPerSec = 5 })

	kpA, _ := crypto.GenerateKeyPair()
	a, err := ConnectDERP(ctx, addr, kpA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	kpB, _ := crypto.GenerateKeyPair()
	b, err := ConnectDERP(ctx, addr, kpB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	keyB, _ := parseKey(kpB.PublicKey)
	time.Sleep(50 * time.Millisecond) // let the server register both sessions

	for i := 0; i < 50; i++ {
		_ = a.Send(keyB, []byte("x"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for srv.Dropped() < 40 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Dropped() < 40 {
		t.Fatalf("expected most of 50 packets dropped at 5/s, dropped %d", srv.Dropped())
	}
	// Delivery within the burst still works.
	select {
	case <-b.Recv():
	case <-time.After(time.Second):
		t.Fatal("packets within the rate must still be relayed")
	}
}
