// Package agent holds behaviour shared by the node and gateway daemons.
package agent

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/dataplane/netcfg"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
)

const popKeepalive = 25 * time.Second

// PoPLink keeps an agent's tunnel to its current edge PoP. The PoP peer carries
// the whole overlay prefix (it relays to everything the agent has no direct
// path to); direct peers with longer prefixes win by WireGuard's longest-match.
type PoPLink struct {
	WG        *wireguard.Manager
	Interface string
	// OSRoutes sends the overlay prefixes into the interface. Disable it for
	// userspace (netstack) devices that have no host interface.
	OSRoutes bool

	mu      sync.Mutex
	current string // public key of the PoP currently linked
}

// Connect points the overlay prefixes at pop, removing the previous PoP peer so
// two PoPs never claim the same prefix.
func (l *PoPLink) Connect(pop core.EdgePoP, prefixes []string) error {
	if pop.PublicKey == "" {
		return errors.New("edge pop has no public key")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.current != "" && l.current != pop.PublicKey {
		if err := l.WG.RemovePeer(l.current); err != nil {
			slog.Debug("Could not remove previous PoP peer", "error", err)
		}
	}
	if l.OSRoutes {
		for _, cidr := range prefixes {
			if err := netcfg.AddSubnetRoute(l.Interface, cidr); err != nil {
				slog.Debug("Failed to add overlay route", "cidr", cidr, "error", err)
			}
		}
	}
	if err := l.WG.ApplyPeer(wireguard.PeerConfig{
		PublicKey:           pop.PublicKey,
		Endpoint:            pop.PublicEndpoint,
		AllowedIPs:          prefixes,
		PersistentKeepalive: popKeepalive,
	}); err != nil {
		return err
	}
	l.current = pop.PublicKey
	return nil
}
