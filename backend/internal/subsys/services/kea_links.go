package services

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// KeaLinkMonitor handles interfaces which were unavailable when Kea opened
// its sockets. Call Reconcile under the same lock as Apply/rollback.
// No subprocess is started while link/address state is unchanged.
type KeaLinkMonitor struct {
	runner    system.Runner
	scan      func(*config.Config) (map[string]string, error)
	ready     map[string]string
	current   *config.Config
	subscribe func(context.Context) (<-chan error, error)
}

func NewKeaLinkMonitor(r system.Runner) *KeaLinkMonitor {
	return &KeaLinkMonitor{runner: r, scan: scanKeaLinks, subscribe: subscribeKeaLinks}
}

func (m *KeaLinkMonitor) Reconcile(ctx context.Context, cfg *config.Config) error {
	if cfg != m.current {
		m.ready = nil
		m.current = cfg
	}
	if cfg == nil || !cfg.DHCP.Enabled || cfg.DHCP.Provider != "kea" {
		m.ready = nil
		return nil
	}
	ready, err := m.scan(cfg.RuntimeNetworkConfig())
	if err != nil {
		return fmt.Errorf("интерфейсы Kea: %w", err)
	}
	reload := false
	for name, state := range ready {
		if m.ready[name] != state {
			reload = true
			break
		}
	}
	if reload {
		// SIGHUP re-detects interfaces and opens sockets without replacing
		// the process or discarding leases. Do not signal the LFC subprocess.
		if _, err := m.runner.Run(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=HUP", keaUnit); err != nil {
			// Leave state unacknowledged so a transient failure is retried.
			return fmt.Errorf("обновление DHCP-сокетов Kea: %w", err)
		}
	}
	// Forget lost links as well, so their return triggers a new scan in Kea.
	m.ready = ready
	return nil
}

// Run blocks on kernel events in steady state. Timers exist only to coalesce
// events or retry a failed operation. maintain serializes reconciliation with
// configuration application and rollback.
func (m *KeaLinkMonitor) Run(ctx context.Context, maintain func(context.Context, func(*config.Config) error) error, logf func(string, ...any)) {
	m.runEvents(ctx, maintain, logf, 100*time.Millisecond, 5*time.Second)
}

func (m *KeaLinkMonitor) runEvents(ctx context.Context, maintain func(context.Context, func(*config.Config) error) error, logf func(string, ...any), batch, retry time.Duration) {
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
				m.ready = nil
				if timer != nil {
					timer.Stop()
				}
				tick = nil
				schedule(retry)
			} else {
				if err != nil {
					logf("netlink DHCP: %v", err)
					m.ready = nil
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
					logf("подписка netlink DHCP: %v", err)
					schedule(retry)
					continue
				}
				// Subscribe before taking the snapshot; queued events cover
				// changes concurrent with this reconciliation.
				m.ready = nil
			}
			if err := maintain(ctx, func(cfg *config.Config) error { return m.Reconcile(ctx, cfg) }); err != nil && ctx.Err() == nil {
				logf("готовность интерфейсов DHCP: %v", err)
				schedule(retry)
			}
		}
	}
}

func scanKeaLinks(cfg *config.Config) (map[string]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return keaReadyLinks(cfg, ifaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() })
}

func keaReadyLinks(cfg *config.Config, ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) (map[string]string, error) {
	names := map[string]string{}
	for _, i := range cfg.Interfaces {
		if i.Enabled {
			names[i.ID] = i.Name
		}
	}
	wanted := map[string]map[netip.Addr]bool{}
	for _, n := range cfg.Networks {
		name := names[n.Interface]
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if !n.Enabled || !n.DHCPPool.Enabled || name == "" || err != nil || !prefix.Addr().Is4() {
			continue
		}
		if wanted[name] == nil {
			wanted[name] = map[netip.Addr]bool{}
		}
		wanted[name][prefix.Addr()] = true
	}
	ready := map[string]string{}
	for _, i := range ifaces {
		if len(wanted[i.Name]) == 0 || i.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning {
			continue
		}
		addresses, err := addrs(i)
		if err != nil {
			return nil, err
		}
		var matched []string
		for _, a := range addresses {
			prefix, err := netip.ParsePrefix(a.String())
			if err == nil && wanted[i.Name][prefix.Addr()] {
				matched = append(matched, prefix.Addr().String())
			}
		}
		if len(matched) != 0 {
			sort.Strings(matched)
			ready[i.Name] = strconv.Itoa(i.Index) + ":" + strings.Join(matched, ",")
		}
	}
	return ready, nil
}
