package tun

import (
	"errors"
	"log/slog"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// Device represents an abstract TUN interface (native OS or userspace channel).
type Device interface {
	Name() string
	Read(packets [][]byte, sizes []int, offset int) (int, error)
	Write(packets [][]byte, offset int) (int, error)
	MTU() (int, error)
	Close() error
	IsSimulated() bool
}

type osDevice struct {
	tun.Device
	name string
}

func (d *osDevice) Name() string {
	return d.name
}

func (d *osDevice) IsSimulated() bool {
	return false
}

// MemoryDevice is a userspace memory-backed TUN device used in unprivileged containers or unit tests.
type MemoryDevice struct {
	mu     sync.Mutex
	name   string
	mtu    int
	inCh   chan []byte
	outCh  chan []byte
	closed bool
}

// NewMemoryDevice creates a memory-backed userspace TUN device.
func NewMemoryDevice(name string, mtu int) *MemoryDevice {
	if mtu <= 0 {
		mtu = 1420
	}
	return &MemoryDevice{
		name:  name,
		mtu:   mtu,
		inCh:  make(chan []byte, 256),
		outCh: make(chan []byte, 256),
	}
}

func (m *MemoryDevice) Name() string { return m.name }

func (m *MemoryDevice) MTU() (int, error) { return m.mtu, nil }

func (m *MemoryDevice) IsSimulated() bool { return true }

func (m *MemoryDevice) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	data, ok := <-m.outCh
	if !ok {
		return 0, os.ErrClosed
	}

	copied := copy(packets[0][offset:], data)
	sizes[0] = copied
	return 1, nil
}

func (m *MemoryDevice) Write(packets [][]byte, offset int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, os.ErrClosed
	}

	for _, pkt := range packets {
		payload := make([]byte, len(pkt)-offset)
		copy(payload, pkt[offset:])
		select {
		case m.inCh <- payload:
		default:
		}
	}
	return len(packets), nil
}

func (m *MemoryDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.inCh)
		close(m.outCh)
	}
	return nil
}

// InjectPacket simulates receiving an IP packet from the OS kernel into the TUN stack.
func (m *MemoryDevice) InjectPacket(pkt []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("device closed")
	}
	select {
	case m.outCh <- pkt:
		return nil
	default:
		return errors.New("memory tun buffer full")
	}
}

// EjectPacket retrieves a packet emitted by the overlay engine to the OS.
func (m *MemoryDevice) EjectPacket() ([]byte, error) {
	pkt, ok := <-m.inCh
	if !ok {
		return nil, os.ErrClosed
	}
	return pkt, nil
}

// CreateTUN attempts to create a real kernel TUN adapter.
// If running without root/admin privileges, it gracefully falls back to MemoryDevice.
func CreateTUN(name string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = 1420
	}

	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		slog.Warn("Running in unprivileged userspace TUN mode (fallback from kernel TUN)", "device", name, "reason", err)
		return NewMemoryDevice(name, mtu), nil
	}

	realName, err := dev.Name()
	if err != nil {
		realName = name
	}

	return &osDevice{
		Device: dev,
		name:   realName,
	}, nil
}
