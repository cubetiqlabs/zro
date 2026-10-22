package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/dataplane/relay"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerConfig defines the parameters for a WireGuard peer.
type PeerConfig struct {
	PublicKey           string        `json:"public_key"`
	PresharedKey        string        `json:"preshared_key,omitempty"`
	Endpoint            string        `json:"endpoint,omitempty"` // "ip:port"
	AllowedIPs          []string      `json:"allowed_ips"`        // ["100.64.0.5/32", "192.168.1.0/24"]
	PersistentKeepalive time.Duration `json:"persistent_keepalive"`
}

// Manager manages WireGuard peers and device state across userspace (wireguard-go) and kernel (wgctrl).
type Manager struct {
	mu            sync.Mutex
	interfaceName string
	privateKey    string // base64
	listenPort    int
	tunDevice     tun.Device
	userDevice    *device.Device
	client        *wgctrl.Client
	disableKernel bool
	isSimulated   bool
	isUserspace   bool
	sharedBind    *sharedBind
	mockPeers     map[string]PeerConfig
}

// Option configures a Manager instance.
type Option func(*Manager)

// WithPrivateKey sets the node's WireGuard private key (base64-encoded Curve25519).
func WithPrivateKey(privKey string) Option {
	return func(m *Manager) {
		m.privateKey = privKey
	}
}

// WithListenPort sets the UDP listen port for WireGuard.
func WithListenPort(port int) Option {
	return func(m *Manager) {
		m.listenPort = port
	}
}

// WithTunDevice attaches a userspace TUN device (either OS TUN or MemoryDevice).
func WithTunDevice(dev tun.Device) Option {
	return func(m *Manager) {
		m.tunDevice = dev
	}
}

// WithKernel specifies whether to attempt kernel WireGuard via wgctrl.
func WithKernel(useKernel bool) Option {
	return func(m *Manager) {
		m.disableKernel = !useKernel
	}
}

// WithSharedSocket makes the userspace WireGuard device use an existing UDP
// socket. Non-WireGuard datagrams are handed to handler. Sharing the socket is
// required for STUN-discovered endpoints and hole punching to match the NAT
// mapping WireGuard actually receives on.
func WithSharedSocket(udpConn *net.UDPConn, handler ControlPacketHandler) Option {
	return func(m *Manager) {
		m.sharedBind = newSharedBind(udpConn, handler)
	}
}

// NewManager creates a WireGuard device manager.
// By default, if a tunDevice is provided (or when running userspace WireGuard),
// it initializes a wireguard-go userspace Device with real Noise protocol encryption.
// If kernel mode is preferred and available, it attaches wgctrl.
func NewManager(interfaceName string, opts ...Option) (*Manager, error) {
	m := &Manager{
		interfaceName: interfaceName,
		mockPeers:     make(map[string]PeerConfig),
	}

	for _, opt := range opts {
		opt(m)
	}

	// 1. If TUN device is provided, initialize userspace wireguard-go engine
	if m.tunDevice != nil {
		var bind conn.Bind = conn.NewDefaultBind()
		if m.sharedBind != nil {
			bind = m.sharedBind
		}
		logger := device.NewLogger(device.LogLevelSilent, fmt.Sprintf("[%s] ", interfaceName))
		userDev := device.NewDevice(m.tunDevice, bind, logger)
		m.userDevice = userDev
		m.isUserspace = true

		if m.privateKey != "" {
			if err := m.applyLocalKeyAndPort(); err != nil {
				slog.Warn("Failed to configure initial WireGuard key/port on userspace device", "error", err)
			}
		}

		// Bring the device up explicitly. Without this the bind is only opened
		// by a TUN EventUp, which never arrives if the interface is not
		// configured by the host (our default in containers).
		if err := userDev.Up(); err != nil {
			return nil, fmt.Errorf("failed to bring up userspace WireGuard device: %w", err)
		}

		slog.Debug("Initialized userspace WireGuard engine", "interface", interfaceName, "port", m.listenPort)
		return m, nil
	}

	if m.disableKernel {
		m.isSimulated = true
		return m, nil
	}

	// 2. Fallback to OS kernel WireGuard client (wgctrl) if no TUN device explicitly passed
	client, err := wgctrl.New()
	if err != nil {
		slog.Debug("Running WireGuard in in-memory state mode (no kernel wg and no tun dev)", "interface", interfaceName, "error", err)
		m.isSimulated = true
		return m, nil
	}

	m.client = client
	return m, nil
}

func (m *Manager) applyLocalKeyAndPort() error {
	if m.userDevice == nil || m.privateKey == "" {
		return nil
	}

	privBytes, err := base64.StdEncoding.DecodeString(m.privateKey)
	if err != nil || len(privBytes) != 32 {
		return fmt.Errorf("invalid base64 private key: %w", err)
	}

	privHex := hex.EncodeToString(privBytes)
	uapi := fmt.Sprintf("private_key=%s\n", privHex)
	if m.listenPort > 0 {
		uapi += fmt.Sprintf("listen_port=%d\n", m.listenPort)
	}

	return m.userDevice.IpcSet(uapi)
}

// SetPrivateKey updates the local device's WireGuard private key and reconfigures the device.
func (m *Manager) SetPrivateKey(privKeyBase64 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.privateKey = privKeyBase64
	return m.applyLocalKeyAndPort()
}

// Close releases the WireGuard control client and shuts down the userspace engine.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.userDevice != nil {
		m.userDevice.Close()
		m.userDevice = nil
	}
	if m.client != nil {
		err := m.client.Close()
		m.client = nil
		return err
	}
	return nil
}

// ApplyPeer adds or updates a peer on the WireGuard device.
func (m *Manager) ApplyPeer(cfg PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-applying an unchanged peer would reset the endpoint WireGuard learned
	// from the peer's authenticated packets back to a possibly stale one.
	if prev, ok := m.mockPeers[cfg.PublicKey]; ok && samePeer(prev, cfg) {
		return nil
	}
	return m.applyLocked(cfg)
}

// applyLocked programs a peer unconditionally. m.mu must be held.
func (m *Manager) applyLocked(cfg PeerConfig) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil || len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}
	pubHex := hex.EncodeToString(pubKeyBytes)
	var applyErr error

	// 1. Configure userspace wireguard-go device via WireGuard UAPI protocol
	if m.userDevice != nil {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("public_key=%s\n", pubHex))
		sb.WriteString("replace_allowed_ips=true\n")

		if cfg.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", cfg.Endpoint))
		}
		// Always written: 0 turns a previously enabled keepalive off, and the
		// 0 -> n transition is what makes WireGuard send a keepalive (and so
		// start a handshake) right away.
		sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", int(cfg.PersistentKeepalive.Seconds())))
		if cfg.PresharedKey != "" {
			if pskBytes, err := base64.StdEncoding.DecodeString(cfg.PresharedKey); err == nil && len(pskBytes) == 32 {
				sb.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(pskBytes)))
			}
		}
		for _, ipStr := range cfg.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", ipStr))
		}

		if err := m.userDevice.IpcSet(sb.String()); err != nil {
			applyErr = fmt.Errorf("configuring peer: %w", err)
		}
	}

	// 2. Configure kernel device if wgctrl is active
	if m.client != nil {
		var wgPubKey wgtypes.Key
		copy(wgPubKey[:], pubKeyBytes)

		peerConfig := wgtypes.PeerConfig{
			PublicKey:         wgPubKey,
			UpdateOnly:        false,
			ReplaceAllowedIPs: true,
		}

		if cfg.Endpoint != "" {
			if udpAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint); err == nil {
				peerConfig.Endpoint = udpAddr
			}
		}

		for _, ipStr := range cfg.AllowedIPs {
			if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
				peerConfig.AllowedIPs = append(peerConfig.AllowedIPs, *ipNet)
			}
		}

		if cfg.PersistentKeepalive > 0 {
			peerConfig.PersistentKeepaliveInterval = &cfg.PersistentKeepalive
		}

		deviceConfig := wgtypes.Config{
			Peers: []wgtypes.PeerConfig{peerConfig},
		}

		if err := m.client.ConfigureDevice(m.interfaceName, deviceConfig); err != nil {
			slog.Debug("OS WireGuard configure failed, maintaining peer in memory", "error", err)
		}
	}

	if applyErr != nil {
		return applyErr
	}
	m.mockPeers[cfg.PublicKey] = cfg // only remember what was actually applied
	return nil
}

// LastHandshake returns when the userspace device last completed a handshake
// with the peer; the zero time means never.
func (m *Manager) LastHandshake(publicKeyBase64 string) (time.Time, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(raw) != 32 {
		return time.Time{}, fmt.Errorf("invalid base64 public key: %w", err)
	}
	m.mu.Lock()
	dev := m.userDevice
	m.mu.Unlock()
	if dev == nil {
		return time.Time{}, errors.New("handshake state needs a userspace device")
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return time.Time{}, err
	}

	want := hex.EncodeToString(raw)
	var inPeer bool
	var sec, nsec int64
	for _, line := range strings.Split(dump, "\n") {
		key, val, _ := strings.Cut(line, "=")
		switch key {
		case "public_key":
			inPeer = val == want
		case "last_handshake_time_sec":
			if inPeer {
				sec, _ = strconv.ParseInt(val, 10, 64)
			}
		case "last_handshake_time_nsec":
			if inPeer {
				nsec, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}, nil
	}
	return time.Unix(sec, nsec), nil
}

// Nudge makes WireGuard start a handshake with the peer now instead of waiting
// for its retry timer. WireGuard refuses to start a new (non-retry) handshake
// within 5s of the last attempt, and that timer lives in the peer object, so the
// peer is removed and re-added. Only call it for a peer with no session yet,
// when the remote side is known to be ready (for example it just learned about
// this node). A peer without a keepalive is left alone: it initiates only when
// it has traffic.
func (m *Manager) Nudge(publicKeyBase64 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.mockPeers[publicKeyBase64]
	if !ok || cfg.PersistentKeepalive == 0 || m.userDevice == nil {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}
	if err := m.userDevice.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(raw))); err != nil {
		return err
	}
	return m.applyLocked(cfg)
}

// samePeer reports whether two peer configs would program the device identically.
func samePeer(a, b PeerConfig) bool {
	if a.PublicKey != b.PublicKey || a.PresharedKey != b.PresharedKey || a.Endpoint != b.Endpoint ||
		a.PersistentKeepalive != b.PersistentKeepalive || len(a.AllowedIPs) != len(b.AllowedIPs) {
		return false
	}
	seen := make(map[string]struct{}, len(a.AllowedIPs))
	for _, ip := range a.AllowedIPs {
		seen[ip] = struct{}{}
	}
	for _, ip := range b.AllowedIPs {
		if _, ok := seen[ip]; !ok {
			return false
		}
	}
	return true
}

// Reconcile makes the device's peers exactly desired: changed peers are
// re-applied, unchanged ones are left alone, and peers not listed are removed.
// It keeps going after a failure and returns the first error.
func (m *Manager) Reconcile(desired []PeerConfig) error {
	want := make(map[string]struct{}, len(desired))
	var firstErr error
	for _, p := range desired {
		want[p.PublicKey] = struct{}{}
		if err := m.ApplyPeer(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	m.mu.Lock()
	var stale []string
	for key := range m.mockPeers {
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	m.mu.Unlock()

	for _, key := range stale {
		if err := m.RemovePeer(key); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AttachRelay installs a relay transport (DERP) for peers configured with a
// RelayEndpoint. It requires the shared-socket bind.
func (m *Manager) AttachRelay(t relay.Transport) error {
	if m.sharedBind == nil {
		return errors.New("relay requires a shared-socket userspace device")
	}
	m.sharedBind.AttachRelay(t)
	return nil
}

// RemovePeer removes a peer from the WireGuard interface.
func (m *Manager) RemovePeer(publicKeyBase64 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}
	pubHex := hex.EncodeToString(pubKeyBytes)

	delete(m.mockPeers, publicKeyBase64)

	// 1. Remove from userspace device via UAPI
	if m.userDevice != nil {
		uapi := fmt.Sprintf("public_key=%s\nremove=true\n", pubHex)
		_ = m.userDevice.IpcSet(uapi)
	}

	// 2. Remove from kernel device
	if m.client != nil {
		var wgPubKey wgtypes.Key
		copy(wgPubKey[:], pubKeyBytes)

		deviceConfig := wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: wgPubKey,
					Remove:    true,
				},
			},
		}
		_ = m.client.ConfigureDevice(m.interfaceName, deviceConfig)
	}

	return nil
}

// ListPeers returns configured peers.
func (m *Manager) ListPeers() ([]PeerConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]PeerConfig, 0, len(m.mockPeers))
	for _, p := range m.mockPeers {
		result = append(result, p)
	}
	return result, nil
}

// IsUserspace returns true if running userspace wireguard-go.
func (m *Manager) IsUserspace() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isUserspace
}

// IsSimulated returns true if running without kernel or userspace device.
func (m *Manager) IsSimulated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isSimulated
}
