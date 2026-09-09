package channels

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type channelState struct {
	Failures  int
	Successes int
	Down      bool
	Next      time.Time
}

// Run continuously verifies enabled channel probes. A channel transition is
// applied to its own policy-routing rule/table, so unrelated traffic and the
// router's main default route are never touched.
func (s *Subsystem) Run(ctx context.Context, current func() *config.Config) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx, current())
		}
	}
}

func (s *Subsystem) tick(ctx context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Before(s.pausedUntil) {
		return
	}
	wanted := map[string]bool{}
	for _, ch := range enabledChannels(cfg) {
		// Recreating a TUN device removes its routes. Repair its own table
		// even with probes disabled or while a fallback rule is selected.
		if s.linkExists(InterfaceName(ch)) {
			if err := s.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
				s.warnf("Канал %s: восстановление маршрута: %v", ch.Name, err)
			}
		}
		if !ch.Probe.Enabled {
			continue
		}
		wanted[ch.ID] = true
		state := s.states[ch.ID]
		if state == nil {
			state = &channelState{}
			s.states[ch.ID] = state
		}
		if time.Now().Before(state.Next) {
			continue
		}
		interval := time.Duration(ch.Probe.Interval) * time.Second
		if interval <= 0 {
			interval = 10 * time.Second
		}
		state.Next = time.Now().Add(interval)
		ok := s.Probe(ctx, ch, InterfaceName(ch))
		s.record(ctx, cfg, ch, state, ok)
	}
	for id := range s.states {
		if !wanted[id] {
			delete(s.states, id)
		}
	}
	// A reserve can fail or recover while its parent stays down. Reconcile
	// after all probes so routing follows the complete, current fallback chain.
	for _, ch := range enabledChannels(cfg) {
		if state := s.states[ch.ID]; state != nil && state.Down {
			if err := s.failChannel(ctx, cfg, ch); err != nil {
				s.warnf("Канал %s: обновление резервного маршрута: %v", ch.Name, err)
			}
		}
	}
}

func (s *Subsystem) record(ctx context.Context, cfg *config.Config, ch config.Channel, state *channelState, ok bool) {
	fail := ch.Probe.FailThreshold
	if fail <= 0 {
		fail = 3
	}
	rise := ch.Probe.RiseThreshold
	if rise <= 0 {
		rise = 2
	}
	if ok {
		state.Failures = 0
		state.Successes++
		if state.Down && state.Successes >= rise {
			if err := s.restoreChannel(ctx, ch); err != nil {
				s.warnf("Канал %s снова доступен, но маршрут не восстановлен: %v", ch.Name, err)
				return
			}
			state.Down = false
			s.infof("Канал %s восстановлен", ch.Name)
		}
		return
	}
	state.Successes = 0
	state.Failures++
	if state.Down || state.Failures < fail {
		return
	}
	if err := s.failChannel(ctx, cfg, ch); err != nil {
		s.warnf("Канал %s недоступен, аварийный режим не применён: %v", ch.Name, err)
		return
	}
	state.Down = true
	s.warnf("Канал %s недоступен, режим отказа: %s", ch.Name, ch.FailMode)
}

func (s *Subsystem) failChannel(ctx context.Context, cfg *config.Config, ch config.Channel) error {
	target := ch
	seen := map[string]bool{}
	for {
		if seen[target.ID] {
			return s.ensureRuleTable(ctx, ch, TableNumber(ch))
		}
		seen[target.ID] = true
		switch target.FailMode {
		case "direct":
			return s.removeChannelRule(ctx, ch)
		case "fallback":
			fallback, ok := channelByID(cfg, target.Fallback)
			if !ok {
				return s.ensureRuleTable(ctx, ch, TableNumber(ch))
			}
			if fallback.Type == "direct" {
				return s.removeChannelRule(ctx, ch)
			}
			if state := s.states[fallback.ID]; state != nil && state.Down {
				target = fallback
				continue
			}
			return s.ensureRuleTable(ctx, ch, TableNumber(fallback))
		default: // block
			// Retain the device route for recovery probes. The lower-priority
			// blackhole prevents WAN fallthrough when the device disappears.
			if err := s.ensureRoutes(ctx, target, InterfaceName(target)); err != nil {
				return err
			}
			return s.ensureRuleTable(ctx, ch, TableNumber(target))
		}
	}
}

func (s *Subsystem) removeChannelRule(ctx context.Context, ch config.Channel) error {
	priority := fmt.Sprint(Priority(ch))
	out, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return fmt.Errorf("чтение правил канала: %w", err)
	}
	if !hasRulePriority(out, priority) {
		return s.refreshChannelUDP(ctx, ch, false)
	}
	if _, err := s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority); err != nil {
		return fmt.Errorf("удаление правила канала: %w", err)
	}
	return s.refreshChannelUDP(ctx, ch, true)
}

func (s *Subsystem) restoreChannel(ctx context.Context, ch config.Channel) error {
	if err := s.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
		return err
	}
	return s.ensureRule(ctx, ch)
}

func (s *Subsystem) probe(ctx context.Context, ch config.Channel, iface string) bool {
	// Xray's TUN answers echo locally, even when its remote server is down.
	// Guard persisted configurations too: a local reply must not restore a VPN.
	if ch.Type == "xray" && (ch.Probe.Type == "icmp" || ch.Probe.Type == "") {
		return false
	}
	if ch.Type == "xray" && ch.Probe.Type == "tcp" && ch.Probe.TCPResponse == "" {
		return false
	}
	timeout := ch.Probe.Timeout
	if timeout <= 0 {
		timeout = 3
	}
	for _, target := range ch.Probe.Targets {
		var err error
		switch ch.Probe.Type {
		case "http":
			_, err = s.Runner.Run(ctx, "curl", "--interface", iface, "--fail", "--silent", "--max-time", fmt.Sprint(timeout), target)
		case "tcp":
			host, port, splitErr := net.SplitHostPort(target)
			if splitErr != nil {
				continue
			}
			if ch.Probe.TCPResponse != "" {
				err = probeTCPExchange(ctx, iface, net.JoinHostPort(host, port), time.Duration(timeout)*time.Second, ch.Probe.TCPRequest, ch.Probe.TCPResponse)
			} else {
				err = probeTCP(ctx, iface, net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
			}
		default:
			family := "-4"
			if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
				family = "-6"
			}
			_, err = s.Runner.Run(ctx, "ping", family, "-I", iface, "-c", "1", "-W", fmt.Sprint(timeout), target)
		}
		if err == nil {
			return true
		}
	}
	return false
}

func channelByID(cfg *config.Config, id string) (config.Channel, bool) {
	for _, ch := range cfg.Channels {
		if ch.ID == id && ch.Enabled {
			return ch, true
		}
	}
	return config.Channel{}, false
}

func (s *Subsystem) infof(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Infof(format, args...)
	}
}

func (s *Subsystem) warnf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Warnf(format, args...)
	}
}
