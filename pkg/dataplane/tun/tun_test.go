package tun

import (
	"bytes"
	"testing"
)

func TestTUNMemoryDevice(t *testing.T) {
	dev := NewMemoryDevice("zro-test0", 1420)
	defer dev.Close()

	if dev.Name() != "zro-test0" {
		t.Fatalf("expected name zro-test0, got %s", dev.Name())
	}

	mtu, err := dev.MTU()
	if err != nil || mtu != 1420 {
		t.Fatalf("expected mtu 1420, got %d (err: %v)", mtu, err)
	}

	// 1. Test Write packet into TUN device
	rawPacket := []byte{0x45, 0x00, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04} // simulated IPv4 header
	packets := [][]byte{rawPacket}
	n, err := dev.Write(packets, 0)
	if err != nil || n != 1 {
		t.Fatalf("dev.Write failed: n=%d, err=%v", n, err)
	}

	// Eject packet out
	ejected, err := dev.EjectPacket()
	if err != nil || !bytes.Equal(ejected, rawPacket) {
		t.Fatalf("ejected packet mismatch: %v", err)
	}

	// 2. Test Inject packet into TUN device and Read out
	injectData := []byte("INJECTED_IP_PACKET_FROM_KERNEL")
	if err := dev.InjectPacket(injectData); err != nil {
		t.Fatalf("InjectPacket failed: %v", err)
	}

	readBuf := make([][]byte, 1)
	readBuf[0] = make([]byte, 2048)
	sizes := make([]int, 1)

	readN, err := dev.Read(readBuf, sizes, 0)
	if err != nil || readN != 1 {
		t.Fatalf("dev.Read failed: readN=%d, err=%v", readN, err)
	}

	readBytes := readBuf[0][:sizes[0]]
	if !bytes.Equal(readBytes, injectData) {
		t.Fatalf("read packet mismatch: expected %s, got %s", injectData, readBytes)
	}
}

func TestCreateTUNGracefulFallback(t *testing.T) {
	// Should not crash even on non-root test environments
	dev, err := CreateTUN("zro-auto0", 1420)
	if err != nil {
		t.Fatalf("CreateTUN returned unexpected fatal error: %v", err)
	}
	defer dev.Close()

	if dev.Name() == "" {
		t.Fatalf("expected non-empty device name")
	}
}
