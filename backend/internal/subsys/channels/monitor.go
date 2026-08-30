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
	for _, ch := range enabledWireGuard(cfg) {
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
	switch ch.FailMode {
	case "direct":
		_, _ = s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
		return nil
	case "fallback":
		fallback, ok := channelByID(cfg, ch.Fallback)
		if !ok || fallback.Type == "direct" {
			_, _ = s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
			return nil
		}
		return s.ensureRuleTable(ctx, ch, TableNumber(fallback))
	default: // block
		table := fmt.Sprint(TableNumber(ch))
		_, _ = s.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", table)
		_, err := s.Runner.Run(ctx, "ip", "-4", "route", "replace", "blackhole", "default", "metric", "1000", "table", table, "proto", fmt.Sprint(config.RouteProto))
		return err
	}
}

func (s *Subsystem) restoreChannel(ctx context.Context, ch config.Channel) error {
	if err := s.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
		return err
	}
	return s.ensureRule(ctx, ch)
}

func (s *Subsystem) probe(ctx context.Context, ch config.Channel, iface string) bool {
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
			_, err = s.Runner.Run(ctx, "curl", "--interface", iface, "--silent", "--max-time", fmt.Sprint(timeout), "telnet://"+host+":"+port)
		default:
			_, err = s.Runner.Run(ctx, "ping", "-4", "-I", iface, "-c", "1", "-W", fmt.Sprint(timeout), target)
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
