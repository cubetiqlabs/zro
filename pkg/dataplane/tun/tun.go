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
	tun.Device
	IsSimulated() bool
	DeviceName() string
}

type osDevice struct {
	tun.Device
	name string
}

func (d *osDevice) DeviceName() string {
	if n, err := d.Device.Name(); err == nil {
		return n
	}
	return d.name
}

func (d *osDevice) IsSimulated() bool {
	return false
}

var errDeviceClosed = errors.New("device closed")

// MemoryDevice is a userspace memory-backed TUN device used in unprivileged containers or unit tests.
type MemoryDevice struct {
	mu      sync.Mutex
	name    string
	mtu     int
	inCh    chan []byte
	outCh   chan []byte
	eventCh chan tun.Event
	closed  bool
}

// NewMemoryDevice creates a memory-backed userspace TUN device.
func NewMemoryDevice(name string, mtu int) *MemoryDevice {
	if mtu <= 0 {
		mtu = 1420
	}
	eventCh := make(chan tun.Event, 1)
	eventCh <- tun.EventUp

	return &MemoryDevice{
		name:    name,
		mtu:     mtu,
		inCh:    make(chan []byte, 256),
		outCh:   make(chan []byte, 256),
		eventCh: eventCh,
	}
}

func (m *MemoryDevice) DeviceName() string { return m.name }

func (m *MemoryDevice) Name() (string, error) { return m.name, nil }

func (m *MemoryDevice) File() *os.File { return nil }

func (m *MemoryDevice) MTU() (int, error) { return m.mtu, nil }

func (m *MemoryDevice) BatchSize() int { return 1 }

func (m *MemoryDevice) Events() <-chan tun.Event { return m.eventCh }

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
		close(m.eventCh)
	}
	return nil
}

// InjectPacket simulates receiving an IP packet from the OS kernel into the TUN stack.
func (m *MemoryDevice) InjectPacket(pkt []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errDeviceClosed
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

// Hairpin forwards every packet WireGuard delivers to the device straight back
// into it, until the device closes. A kernel TUN does this through IP routing;
// a memory device has no kernel, so a relay (edge PoP) running on one needs this
// to forward between its peers in userspace.
func (m *MemoryDevice) Hairpin() {
	for {
		pkt, err := m.EjectPacket()
		if err != nil {
			return
		}
		if err := m.InjectPacket(pkt); err != nil {
			if errors.Is(err, errDeviceClosed) {
				return
			}
			// buffer full: drop, like an overloaded router; transports retransmit
		}
	}
}

var ensureDevNetTun func()

// CreateTUN attempts to create a real kernel TUN adapter.
// If running without root/admin privileges, it gracefully falls back to MemoryDevice.
func CreateTUN(name string, mtu int) (Device, error) {
	if ensureDevNetTun != nil {
		ensureDevNetTun()
	}

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
