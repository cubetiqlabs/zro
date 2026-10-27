package netstack

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// pump copies packets one stack emits into the other, standing in for WireGuard.
func pump(from, to tun.Device, done <-chan struct{}) {
	buf := make([][]byte, 1)
	buf[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	for {
		if _, err := from.Read(buf, sizes, 0); err != nil {
			return
		}
		pkt := append([]byte(nil), buf[0][:sizes[0]]...)
		select {
		case <-done:
			return
		default:
		}
		_, _ = to.Write([][]byte{pkt}, 0)
	}
}

func TestTCPBetweenTwoStacksWithLateAddress(t *testing.T) {
	devA, a, err := New(1420)
	if err != nil {
		t.Fatal(err)
	}
	devB, b, err := New(1420)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer func() { close(done); devA.Close(); devB.Close() }()
	go pump(devA, devB, done)
	go pump(devB, devA, done)

	// Addresses are assigned after the devices exist, as at enrollment.
	if err := a.AddAddress(netip.MustParseAddr("100.64.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAddress(netip.MustParseAddr("100.64.0.2")); err != nil {
		t.Fatal(err)
	}

	ln, err := b.Listen(8080)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := a.DialContext(ctx, "tcp", "100.64.0.2:8080")
	if err != nil {
		t.Fatalf("dial across stacks: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("echo failed: %q %v", reply, err)
	}

	if _, err := a.DialContext(ctx, "tcp", "example.com:80"); err == nil {
		t.Fatal("hostnames are not resolvable on the overlay and must be rejected")
	}
}

func TestCloseIsIdempotentAndUnblocksRead(t *testing.T) {
	dev, _, err := New(1420)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := dev.Read([][]byte{make([]byte, 2048)}, make([]int, 1), 0)
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = dev.Close()
	_ = dev.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Read must fail after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read was not unblocked by Close")
	}
}

func TestPingBetweenTwoStacks(t *testing.T) {
	devA, a, err := New(1420)
	if err != nil {
		t.Fatal(err)
	}
	devB, b, err := New(1420)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer func() { close(done); devA.Close(); devB.Close() }()
	go pump(devA, devB, done)
	go pump(devB, devA, done)
	_ = a.AddAddress(netip.MustParseAddr("100.64.0.1"))
	_ = b.AddAddress(netip.MustParseAddr("100.64.0.2"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Ping(ctx, netip.MustParseAddr("100.64.0.2")); err != nil {
		t.Fatalf("ping across stacks: %v", err)
	}
}
