package services

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// IGMPproxy caches ifindex/address at startup. Reconcile only actual changes;
// steady-state work is blocked on the existing kernel link subscription.
func (s *IPTV) Reconcile(ctx context.Context, c *config.Config) error {
	if c == nil || !c.IPTV.Enabled {
		return nil
	}
	state, err := s.links(c)
	if err != nil {
		path := filepath.Join(s.StateDir, "iptv.links")
		if _, statErr := os.Stat(path); statErr == nil {
			if owned, ownErr := s.owned(); ownErr != nil {
				return ownErr
			} else if owned {
				if _, stopErr := s.Runner.Run(ctx, "systemctl", "stop", IPTVUnit); stopErr != nil {
					return stopErr
				}
				if removeErr := os.Remove(path); removeErr != nil {
					return removeErr
				}
			}
		}
		return err
	}
	previous, err := os.ReadFile(filepath.Join(s.StateDir, "iptv.links"))
	if err == nil && string(previous) == state {
		return nil
	}
	return s.Apply(ctx, c)
}

func (s *IPTV) Run(ctx context.Context, maintain func(context.Context, func(*config.Config) error) error, logf func(string, ...any)) {
	var events <-chan error
	var timer *time.Timer
	var tick <-chan time.Time
	schedule := func(delay time.Duration) {
		if tick == nil {
			timer = time.NewTimer(delay)
			tick = timer.C
		}
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	schedule(0)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				events = nil
				schedule(5 * time.Second)
			} else {
				schedule(100 * time.Millisecond)
			}
		case <-tick:
			tick = nil
			if events == nil {
				var err error
				events, err = subscribeIPv4Links(ctx)
				if err != nil {
					logf("IPTV: подписка на сеть: %v", err)
					schedule(5 * time.Second)
					continue
				}
			}
			if err := maintain(ctx, func(c *config.Config) error { return s.Reconcile(ctx, c) }); err != nil && ctx.Err() == nil {
				logf("IPTV: восстановление интерфейсов: %v", err)
				schedule(5 * time.Second)
			}
		}
	}
}
