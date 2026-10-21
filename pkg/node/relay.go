package node

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/dataplane/derp"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
)

// pathMode is how the node reaches its edge PoP.
type pathMode int

const (
	pathUDP   pathMode = iota // WireGuard over UDP (normal)
	pathRelay                 // WireGuard datagrams tunnelled over the PoP's DERP TCP relay
)

const udpFailuresBeforeRelay = 2

// nextPath decides the PoP path after a UDP probe. The probe is independent of
// WireGuard's own traffic, so UDP is restored as soon as it works again.
func nextPath(cur pathMode, udpOK bool, consecutiveFails int, relayUp bool) pathMode {
	switch {
	case udpOK:
		return pathUDP
	case consecutiveFails >= udpFailuresBeforeRelay && relayUp:
		return pathRelay
	default:
		return cur
	}
}

// relayState tracks the DERP connection used as the fallback path.
type relayState struct {
	mu     sync.Mutex
	pop    core.EdgePoP
	up     bool
	mode   pathMode
	wakeup chan struct{}
}

func newRelayState() *relayState { return &relayState{wakeup: make(chan struct{}, 1)} }

func (r *relayState) isUp() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up
}

func (r *relayState) setUp(up bool) {
	r.mu.Lock()
	r.up = up
	r.mu.Unlock()
}

// target records the PoP the relay should connect to and wakes the worker.
func (r *relayState) target(pop core.EdgePoP) {
	r.mu.Lock()
	changed := r.pop.PublicEndpoint != pop.PublicEndpoint || r.pop.PublicKey != pop.PublicKey
	r.pop = pop
	r.mu.Unlock()
	if changed {
		select {
		case r.wakeup <- struct{}{}:
		default:
		}
	}
}

func (r *relayState) current() core.EdgePoP {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pop
}

// relayWorker keeps one DERP connection to the current PoP and attaches it to
// WireGuard, reconnecting with backoff. Having it ready costs one idle TCP
// connection and lets the node switch paths without a new handshake delay.
func (d *Daemon) relayWorker(ctx context.Context) {
	defer d.wg.Done()
	backoff := time.Second
	for ctx.Err() == nil {
		pop := d.relay.current()
		if pop.PublicEndpoint == "" {
			select {
			case <-ctx.Done():
				return
			case <-d.relay.wakeup:
			}
			continue
		}

		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		client, err := derp.ConnectDERP(dialCtx, pop.PublicEndpoint, d.keyPair)
		cancel()
		if err != nil {
			slog.Debug("DERP relay unavailable", "pop", pop.PoPCode, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-d.relay.wakeup:
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second

		if err := d.wgManager.AttachRelay(client); err != nil {
			_ = client.Close()
			return // this device cannot relay (not a shared-socket userspace device)
		}
		d.relay.setUp(true)
		slog.Info("Connected to Edge DERP relay fallback", "pop", pop.PoPCode, "endpoint", pop.PublicEndpoint)

		select {
		case <-ctx.Done():
		case <-client.Done():
		case <-d.relay.wakeup: // the PoP changed
		}
		d.relay.setUp(false)
		_ = client.Close()
	}
}

// applyPath points the PoP peer at UDP or at the relay.
func (d *Daemon) applyPath(pop core.EdgePoP, mode pathMode) error {
	if mode == pathRelay {
		pop.PublicEndpoint = wireguard.RelayEndpoint(pop.PublicKey)
	}
	if err := d.popLink.Connect(pop, d.overlayPrefixes); err != nil {
		return err
	}
	d.relay.mu.Lock()
	d.relay.mode = mode
	d.relay.mu.Unlock()
	return nil
}
