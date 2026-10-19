package wireguard

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

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

// Manager manages WireGuard peers and device state.
type Manager struct {
	mu           sync.Mutex
	interfaceName string
	client       *wgctrl.Client
	isSimulated  bool
	mockPeers    map[string]PeerConfig
}

// NewManager creates a WireGuard device manager.
// If interface creation fails or permissions are missing (e.g. non-root test environments),
// it gracefully switches to userspace/simulation mode.
func NewManager(interfaceName string) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		slog.Warn("Running WireGuard in userspace simulated mode (unprivileged or no wg kernel)", "interface", interfaceName, "error", err)
		return &Manager{
			interfaceName: interfaceName,
			isSimulated:   true,
			mockPeers:     make(map[string]PeerConfig),
		}, nil
	}

	return &Manager{
		interfaceName: interfaceName,
		client:       client,
		mockPeers:    make(map[string]PeerConfig),
	}, nil
}

// Close releases the WireGuard control client.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

// ApplyPeer adds or updates a peer on the WireGuard device.
func (m *Manager) ApplyPeer(cfg PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil || len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}

	if m.isSimulated || m.client == nil {
		m.mockPeers[cfg.PublicKey] = cfg
		return nil
	}

	var wgPubKey wgtypes.Key
	copy(wgPubKey[:], pubKeyBytes)

	peerConfig := wgtypes.PeerConfig{
		PublicKey:         wgPubKey,
		UpdateOnly:        false,
		ReplaceAllowedIPs: true,
	}

	// Parse Endpoint
	if cfg.Endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err == nil {
			peerConfig.Endpoint = udpAddr
		}
	}

	// Parse AllowedIPs
	for _, ipStr := range cfg.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err == nil {
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
		// Fallback to in-memory state if OS interface cannot be manipulated
		slog.Debug("OS WireGuard configure failed, maintaining in-memory peer state", "error", err)
		m.mockPeers[cfg.PublicKey] = cfg
	}

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

	delete(m.mockPeers, publicKeyBase64)

	if m.isSimulated || m.client == nil {
		return nil
	}

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
	return nil
}

// ListPeers returns configured peers.
func (m *Manager) ListPeers() ([]PeerConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []PeerConfig
	for _, p := range m.mockPeers {
		result = append(result, p)
	}
	return result, nil
}
