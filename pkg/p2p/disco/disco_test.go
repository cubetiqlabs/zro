package disco

import (
	"net"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/crypto"
)

func TestDiscoPingPong(t *testing.T) {
	// Node 1
	kp1, _ := crypto.GenerateKeyPair()
	conn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind conn1: %v", err)
	}
	defer conn1.Close()
	disco1 := NewEngine(kp1, conn1)

	// Node 2
	kp2, _ := crypto.GenerateKeyPair()
	conn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind conn2: %v", err)
	}
	defer conn2.Close()
	disco2 := NewEngine(kp2, conn2)

	// Run reader loop for Node 1
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := conn1.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = disco1.HandlePacket(buf[:n], from)
		}
	}()

	// Run reader loop for Node 2
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := conn2.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = disco2.HandlePacket(buf[:n], from)
		}
	}()

	// Node 1 sends discovery ping to Node 2
	dest := conn2.LocalAddr().String()
	rtt, reflexiveAddr, err := disco1.SendPing(dest, 1*time.Second)
	if err != nil {
		t.Fatalf("disco ping failed: %v", err)
	}

	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %v", rtt)
	}

	if reflexiveAddr == nil || reflexiveAddr.Port != conn2.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("unexpected reflexive addr: %v", reflexiveAddr)
	}
}
