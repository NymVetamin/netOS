package samba

import (
	"context"
	"fmt"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// DiscoveryMonitor repairs wsdd2's interface selection after address changes.
// Debian wsdd2 1.8.7 can replace the selected interface index with the index
// from an unrelated RTM_NEWADDR. A HUP keeps that index; restart only the
// discovery process, never Samba or its established file sessions.
type DiscoveryMonitor struct {
	runner    system.Runner
	subscribe func(context.Context) (<-chan error, error)
}

func NewDiscoveryMonitor(r system.Runner) *DiscoveryMonitor {
	return &DiscoveryMonitor{runner: r, subscribe: subscribeDiscoveryAddresses}
}

func (m *DiscoveryMonitor) recover(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || !cfg.Samba.Enabled || !cfg.Samba.Discovery {
		return nil
	}
	for _, n := range cfg.Networks {
		if n.Enabled && selected(cfg.Samba.Networks, n.ID) {
			restartCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			_, err := m.runner.Run(restartCtx, "systemctl", "restart", "netos-wsdd.service")
			if err != nil {
				return fmt.Errorf("перезапуск обнаружения: %w", err)
			}
			return nil
		}
	}
	return nil
}

// Run sleeps on kernel events in steady state. Timers only batch events or
// retry failures. maintain must serialize recovery with Apply and rollback.
func (m *DiscoveryMonitor) Run(ctx context.Context, maintain func(context.Context, func(*config.Config) error) error, logf func(string, ...any)) {
	m.runEvents(ctx, maintain, logf, 500*time.Millisecond, 5*time.Second)
}

func (m *DiscoveryMonitor) runEvents(ctx context.Context, maintain func(context.Context, func(*config.Config) error) error, logf func(string, ...any), batch, retry time.Duration) {
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
		case err, ok := <-events:
			if !ok {
				events = nil
				if timer != nil {
					timer.Stop()
				}
				tick = nil
				schedule(retry)
			} else {
				if err != nil {
					logf("netlink обнаружения: %v", err)

					continue // The source closes next; reconnect with backoff.
				}
				schedule(batch)
			}
		case <-tick:
			tick = nil
			if ctx.Err() != nil {
				return
			}
			if events == nil {
				var err error
				events, err = m.subscribe(ctx)
				if err != nil {
					logf("подписка netlink обнаружения: %v", err)
					schedule(retry)
					continue
				}
				// Recover after subscribing: events cover concurrent address changes,
				// and recovery also repairs state after a lost event stream.
			}
			if err := maintain(ctx, func(cfg *config.Config) error { return m.recover(ctx, cfg) }); err != nil && ctx.Err() == nil {
				logf("восстановление обнаружения: %v", err)
				schedule(retry)
			}
		}
	}
}
