package node

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// A disco pong proves that datagrams cross both NATs. It does not prove that
// WireGuard completed a handshake over that path. A direct /32 peer outranks
// the PoP's overlay prefix, so a dead one black-holes the peer. That happens
// when the responder missed the punch request, or when a NAT mapping expires.
// The watchdog removes such peers so the PoP relays again, then retries later.
const (
	directHandshakeGrace = 8 * time.Second  // first handshake, including one WireGuard retry
	directSilentAfter    = 50 * time.Second // both sides send a keepalive every 20s
	directRetryMin       = 30 * time.Second // first retry after a failed direct path
	directRetryMax       = 10 * time.Minute
	directCheckEvery     = 2 * time.Second
)

// directPath is what the node knows about the direct path to one peer.
type directPath struct {
	overlayIP string
	installed time.Time // zero while traffic goes through the PoP
	rxBytes   uint64    // bytes received from the peer at lastRx
	lastRx    time.Time // when rxBytes last grew
	fails     int
	retryAt   time.Time
}

type directPaths struct {
	mu    sync.Mutex
	paths map[string]*directPath // peer public key
}

func (p *directPaths) get(key, overlayIP string) *directPath {
	if p.paths == nil {
		p.paths = make(map[string]*directPath)
	}
	dp := p.paths[key]
	if dp == nil {
		dp = &directPath{overlayIP: overlayIP}
		p.paths[key] = dp
	}
	return dp
}

// up records a direct path that was just installed.
func (p *directPaths) up(key, overlayIP string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dp := p.get(key, overlayIP)
	dp.installed, dp.lastRx = now, now
}

// down records that the direct path failed or was removed, and schedules a retry.
func (p *directPaths) down(key, overlayIP string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dp := p.get(key, overlayIP)
	dp.installed = time.Time{}
	dp.fails++
	dp.retryAt = now.Add(retryBackoff(dp.fails))
}

func (p *directPaths) forget(key string) {
	p.mu.Lock()
	delete(p.paths, key)
	p.mu.Unlock()
}

// isDirect reports whether the peer currently has an installed direct path.
func (p *directPaths) isDirect(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	dp := p.paths[key]
	return dp != nil && !dp.installed.IsZero()
}

// directAlive reports whether a direct peer installed at installed still
// carries traffic. lastHandshake is zero if there was never one; a handshake
// older than the install belongs to a previous session. lastRx is when bytes
// last arrived from the peer. Keepalives guarantee some every 20s on a live
// path, and a handshake alone can look fresh for minutes after a NAT mapping
// is gone.
func directAlive(now, installed, lastHandshake, lastRx time.Time) bool {
	if lastHandshake.IsZero() || lastHandshake.Before(installed) {
		return now.Sub(installed) < directHandshakeGrace
	}
	return now.Sub(lastRx) < directSilentAfter
}

// retryBackoff doubles from directRetryMin up to directRetryMax.
func retryBackoff(fails int) time.Duration {
	d := directRetryMin
	for i := 1; i < fails && d < directRetryMax; i++ {
		d *= 2
	}
	return min(d, directRetryMax)
}

// initiates reports whether this node opens the direct path to peerKey. Only
// one side initiates; if both did, their handshakes would collide.
func (d *Daemon) initiates(peerKey string) bool {
	return d.keyPair.PublicKey < peerKey
}

// directWorker drops dead direct paths and retries failed ones.
func (d *Daemon) directWorker(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(directCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.checkDirectPaths(ctx, time.Now())
		}
	}
}

func (d *Daemon) checkDirectPaths(ctx context.Context, now time.Time) {
	stats, err := d.wgManager.Stats()
	if err != nil {
		return // no handshake state (kernel device): nothing to judge by
	}

	type retry struct{ key, ip string }
	var dead, retries []retry
	d.direct.mu.Lock()
	for key, dp := range d.direct.paths {
		switch {
		case !dp.installed.IsZero():
			st := stats[key]
			if st.RxBytes != dp.rxBytes {
				dp.rxBytes, dp.lastRx = st.RxBytes, now
			}
			if !directAlive(now, dp.installed, st.LastHandshake, dp.lastRx) {
				dead = append(dead, retry{key, dp.overlayIP})
			}
		case d.cfg.EnableP2P && d.initiates(key) && !dp.retryAt.IsZero() && now.After(dp.retryAt):
			dp.retryAt = now.Add(retryBackoff(dp.fails + 1)) // one attempt in flight at a time
			retries = append(retries, retry{key, dp.overlayIP})
		}
	}
	d.direct.mu.Unlock()

	for _, p := range dead {
		_ = d.wgManager.RemovePeer(p.key)
		d.direct.down(p.key, p.ip, now)
		slog.Warn("Direct path to peer has no live handshake; relaying through the PoP", "peer_ip", p.ip)
	}
	for _, p := range retries {
		go func(ip string) { _, _ = d.DiscoverAndConnectPeer(ctx, ip) }(p.ip)
	}
}
