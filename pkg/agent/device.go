package agent

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cubetiqlabs/zro/pkg/dataplane/netcfg"
	"github.com/cubetiqlabs/zro/pkg/dataplane/netstack"
	"github.com/cubetiqlabs/zro/pkg/dataplane/overlay"
	"github.com/cubetiqlabs/zro/pkg/dataplane/tun"
)

// ModeNetstack selects the unprivileged userspace stack; anything else uses a
// kernel TUN interface.
const ModeNetstack = "netstack"

// Device is an agent's overlay interface: a kernel TUN, or a userspace stack.
type Device struct {
	TUN tun.Device
	// Net opens and accepts overlay connections for this device.
	Net overlay.Network

	iface string
	mtu   int
	stack *netstack.Net // nil for kernel mode
	ipv4  atomic.Value  // string
}

// OpenDevice creates the overlay interface for mode ("netstack" or kernel).
func OpenDevice(mode, iface string, mtu int) (*Device, error) {
	d := &Device{iface: iface, mtu: mtu}
	if mode == ModeNetstack {
		dev, ns, err := netstack.New(mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to create netstack: %w", err)
		}
		d.TUN, d.stack, d.Net = dev, ns, ns
		return d, nil
	}

	dev, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TUN device: %w", err)
	}
	// Bring the link up before creating the WireGuard device; otherwise the
	// kernel reports the TUN as down and wireguard-go closes its bind.
	if err := netcfg.EnsureLinkUp(iface, mtu); err != nil {
		slog.Warn("Could not bring overlay interface up (data plane may be limited)", "interface", iface, "error", err)
	}
	d.TUN = dev
	d.Net = overlay.Host{IP: func() string { s, _ := d.ipv4.Load().(string); return s }}
	return d, nil
}

// Userspace reports whether the device is the in-process stack (no host
// interface, so no OS addresses or routes).
func (d *Device) Userspace() bool { return d.stack != nil }

// Configure assigns the overlay addresses learned at enrollment.
func (d *Device) Configure(v4, v6 string) error {
	d.ipv4.Store(v4)
	if d.stack == nil {
		return netcfg.ConfigureOverlay(d.iface, v4, v6, d.mtu)
	}
	for _, s := range []string{v4, v6} {
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("invalid overlay address %q: %w", s, err)
		}
		if err := d.stack.AddAddress(ip); err != nil {
			return err
		}
	}
	return nil
}
