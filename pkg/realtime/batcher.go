package realtime

import (
	"context"
	"sort"
	"sync"
	"time"
)

// batcher coalesces events: the reader never blocks on a slow handler, and a
// burst of N events costs one handler call.
type batcher struct {
	delay   time.Duration
	handle  func(context.Context, []string)
	mu      sync.Mutex
	pending map[string]struct{}
	wake    chan struct{}
}

func newBatcher(delay time.Duration, handle func(context.Context, []string)) *batcher {
	return &batcher{delay: delay, handle: handle, pending: make(map[string]struct{}), wake: make(chan struct{}, 1)}
}

func (b *batcher) add(name string) {
	b.mu.Lock()
	b.pending[name] = struct{}{}
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default: // a wake-up is already queued
	}
}

func (b *batcher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		}
		sleep(ctx, b.delay) // let the rest of a burst arrive

		b.mu.Lock()
		names := make([]string, 0, len(b.pending))
		for n := range b.pending {
			names = append(names, n)
		}
		b.pending = make(map[string]struct{})
		b.mu.Unlock()

		if len(names) > 0 && ctx.Err() == nil {
			sort.Strings(names)
			b.handle(ctx, names)
		}
	}
}
