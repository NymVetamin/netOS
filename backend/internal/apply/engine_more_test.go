package apply

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type flexibleSubsystem struct {
	name   string
	plan   func(*config.Config, *config.Config) ([]Action, error)
	apply  func(context.Context, *config.Config) error
	health func(context.Context, *config.Config) error
}

func (s flexibleSubsystem) Name() string { return s.name }
func (s flexibleSubsystem) Plan(old, next *config.Config) ([]Action, error) {
	if s.plan != nil {
		return s.plan(old, next)
	}
	return nil, nil
}
func (s flexibleSubsystem) Apply(ctx context.Context, cfg *config.Config) error {
	if s.apply != nil {
		return s.apply(ctx, cfg)
	}
	return nil
}
func (s flexibleSubsystem) Health(ctx context.Context, cfg *config.Config) error {
	if s.health != nil {
		return s.health(ctx, cfg)
	}
	return nil
}

type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) add(level, format string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+":"+format)
}
func (l *recordingLogger) Infof(format string, _ ...any)  { l.add("info", format) }
func (l *recordingLogger) Warnf(format string, _ ...any)  { l.add("warn", format) }
func (l *recordingLogger) Errorf(format string, _ ...any) { l.add("error", format) }

func TestRegisterPlanOrderingErrorsAndTransitionGuards(t *testing.T) {
	e := NewEngine(&recordingLogger{}, false)
	if err := e.Register(flexibleSubsystem{name: "unknown"}); err == nil {
		t.Fatal("unknown subsystem accepted")
	}
	for _, s := range []flexibleSubsystem{
		{name: "dns", plan: func(*config.Config, *config.Config) ([]Action, error) { return []Action{{Target: "dns"}}, nil }},
		{name: "interfaces", plan: func(*config.Config, *config.Config) ([]Action, error) { return []Action{{Target: "if"}}, nil }},
	} {
		if err := e.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	actions, err := e.PlanFrom(nil, validConfig("new"))
	if err != nil || len(actions) != 2 || actions[0].Subsystem != "interfaces" || actions[1].Subsystem != "dns" {
		t.Fatalf("ordered Plan = %#v, %v", actions, err)
	}
	e.subsystems["dns"] = flexibleSubsystem{name: "dns", plan: func(*config.Config, *config.Config) ([]Action, error) { return nil, errors.New("plan failed") }}
	if _, err := e.PlanFrom(nil, validConfig("new")); err == nil || !strings.Contains(err.Error(), "dns") {
		t.Fatalf("plan error = %v", err)
	}
	old, next := validConfig("old"), validConfig("new")
	next.System.Panel.TLS.Mode = "custom"
	if _, err := e.PlanFrom(old, next); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("TLS transition = %v", err)
	}
}

func TestApplyRejectsNilInvalidAndPending(t *testing.T) {
	e := NewEngine(&recordingLogger{}, false)
	if _, err := e.Apply(context.Background(), nil, 1, false); err == nil {
		t.Fatal("nil config accepted")
	}
	invalid := validConfig("")
	if _, err := e.Apply(context.Background(), invalid, 1, false); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := e.Register(flexibleSubsystem{name: "interfaces", plan: disruptivePlan}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("old"), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("new"), 2, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("blocked"), 3, true); err == nil || !strings.Contains(err.Error(), "не подтверждено") {
		t.Fatalf("pending Apply = %v", err)
	}
}

func disruptivePlan(*config.Config, *config.Config) ([]Action, error) {
	return []Action{{Kind: "update", Target: "network", Disruptive: true}}, nil
}

func TestFailedApplyRestoresAndHealthChecksPrevious(t *testing.T) {
	oldHealth := 0
	s := flexibleSubsystem{name: "interfaces", plan: disruptivePlan,
		apply: func(_ context.Context, cfg *config.Config) error {
			if cfg.System.Hostname == "broken" {
				return errors.New("apply failed")
			}
			return nil
		},
		health: func(_ context.Context, cfg *config.Config) error {
			if cfg.System.Hostname == "old" {
				oldHealth++
			}
			return nil
		},
	}
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(s)
	if _, err := e.Apply(context.Background(), validConfig("old"), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("broken"), 2, true); err == nil {
		t.Fatal("broken apply succeeded")
	}
	if oldHealth != 2 {
		t.Fatalf("previous health calls = %d, want initial + rollback", oldHealth)
	}
}

func TestHealthFailureReportsFailedRollbackHealth(t *testing.T) {
	failOld := false
	s := flexibleSubsystem{name: "interfaces", plan: disruptivePlan,
		health: func(_ context.Context, cfg *config.Config) error {
			switch cfg.System.Hostname {
			case "broken":
				return errors.New("new unhealthy")
			case "old":
				if failOld {
					return errors.New("old unhealthy")
				}
			}
			return nil
		},
	}
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(s)
	if _, err := e.Apply(context.Background(), validConfig("old"), 1, false); err != nil {
		t.Fatal(err)
	}
	failOld = true
	_, err := e.Apply(context.Background(), validConfig("broken"), 2, true)
	if err == nil || !strings.Contains(err.Error(), "откат не удался") || !strings.Contains(err.Error(), "new unhealthy") || !strings.Contains(err.Error(), "old unhealthy") {
		t.Fatalf("double health failure = %v", err)
	}
}

func TestManualRollbackUpdatesStateCallbackAndNotice(t *testing.T) {
	healthHosts := []string{}
	s := flexibleSubsystem{name: "interfaces", plan: disruptivePlan, health: func(_ context.Context, cfg *config.Config) error {
		healthHosts = append(healthHosts, cfg.System.Hostname)
		return nil
	}}
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(s)
	if _, err := e.Apply(context.Background(), validConfig("old"), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("new"), 9, true); err != nil {
		t.Fatal(err)
	}
	var callback RollbackInfo
	e.OnRollback = func(info RollbackInfo) { callback = info }
	if err := e.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, _ := e.Pending(); pending {
		t.Fatal("pending remained after rollback")
	}
	if got := e.Current().System.Hostname; got != "old" {
		t.Fatalf("current = %q", got)
	}
	info := e.LastRollback()
	if info == nil || info.Reason != "manual" || info.Revision != 9 || callback.Reason != "manual" {
		t.Fatalf("rollback info = %#v, callback = %#v", info, callback)
	}
	if healthHosts[len(healthHosts)-1] != "old" {
		t.Fatalf("rollback health hosts = %#v", healthHosts)
	}
	e.ClearRollback()
	if e.LastRollback() != nil {
		t.Fatal("rollback notice not cleared")
	}
	if err := e.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without pending succeeded")
	}
}

func TestExpiredRollbackAndObsoleteTimerPaths(t *testing.T) {
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(flexibleSubsystem{name: "interfaces", plan: disruptivePlan})
	if _, err := e.Apply(context.Background(), validConfig("old"), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("new"), 7, true); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	p := e.pending
	p.timer.Stop()
	e.mu.Unlock()
	e.rollbackExpired(p)
	if info := e.LastRollback(); info == nil || info.Reason != "timeout" || e.Current().System.Hostname != "old" {
		t.Fatalf("expired rollback = %#v", info)
	}
	p.cancelled = true
	e.rollbackExpired(p) // cancelled/obsolete callback must be a no-op.
}

func TestFailedManualRollbackKeepsPendingAndSafetyTimer(t *testing.T) {
	failOld := false
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(flexibleSubsystem{name: "interfaces", plan: disruptivePlan, apply: func(_ context.Context, cfg *config.Config) error {
		if failOld && cfg.System.Hostname == "old" {
			return errors.New("restore failed")
		}
		return nil
	}})
	_, _ = e.Apply(context.Background(), validConfig("old"), 1, false)
	_, _ = e.Apply(context.Background(), validConfig("new"), 2, true)
	failOld = true
	if err := e.Rollback(context.Background()); err == nil || !strings.Contains(err.Error(), "restore failed") {
		t.Fatalf("Rollback error = %v", err)
	}
	if pending, _ := e.Pending(); !pending {
		t.Fatal("failed rollback discarded pending transaction")
	}
	e.mu.Lock()
	p := e.pending
	e.mu.Unlock()
	if !p.timer.Stop() {
		t.Fatal("failed manual rollback had already cancelled the safety timer")
	}
	if e.LastRollback() != nil || e.Current().System.Hostname != "new" {
		t.Fatalf("failed rollback changed committed engine state: %#v", e.LastRollback())
	}
}

func TestFirstApplyFailuresAndObsoleteRollback(t *testing.T) {
	for _, stage := range []string{"apply", "health"} {
		t.Run(stage, func(t *testing.T) {
			s := flexibleSubsystem{name: "interfaces"}
			if stage == "apply" {
				s.apply = func(context.Context, *config.Config) error { return errors.New("first apply") }
			} else {
				s.health = func(context.Context, *config.Config) error { return errors.New("first health") }
			}
			e := NewEngine(&recordingLogger{}, false)
			_ = e.Register(s)
			if _, err := e.Apply(context.Background(), validConfig("first"), 1, false); err == nil {
				t.Fatalf("first %s failure ignored", stage)
			}
			if e.Current() != nil {
				t.Fatal("failed first apply became current")
			}
		})
	}
	e := NewEngine(&recordingLogger{}, false)
	p := &pendingCommit{previous: validConfig("old")}
	if err := e.doRollback(context.Background(), p, "manual", "obsolete"); !errors.Is(err, errRollbackObsolete) {
		t.Fatalf("obsolete rollback = %v", err)
	}
}

func TestConfirmFailureKeepsPendingThenSuccessClearsIt(t *testing.T) {
	e := NewEngine(&recordingLogger{}, false)
	_ = e.Register(flexibleSubsystem{name: "interfaces", plan: disruptivePlan})
	_, _ = e.Apply(context.Background(), validConfig("old"), 1, false)
	_, _ = e.Apply(context.Background(), validConfig("new"), 12, true)
	if _, err := e.Confirm(func(int64) error { return errors.New("db down") }); err == nil {
		t.Fatal("commit failure ignored")
	}
	if pending, _ := e.Pending(); !pending {
		t.Fatal("pending lost after commit failure")
	}
	if revision, err := e.Confirm(nil); err != nil || revision != 12 {
		t.Fatalf("Confirm = %d, %v", revision, err)
	}
	if _, err := e.Confirm(nil); err == nil {
		t.Fatal("second Confirm succeeded")
	}
}

func TestDryRunSkipsApplyAndHealth(t *testing.T) {
	calls := 0
	e := NewEngine(&recordingLogger{}, true)
	_ = e.Register(flexibleSubsystem{name: "dns", apply: func(context.Context, *config.Config) error { calls++; return errors.New("must not run") }, health: func(context.Context, *config.Config) error { calls++; return errors.New("must not run") }})
	res, err := e.Apply(context.Background(), validConfig("dry"), 3, true)
	if err != nil || calls != 0 || res.NeedsConfirm {
		t.Fatalf("dry run = %#v, calls=%d, err=%v", res, calls, err)
	}
}

func TestNeedsConfirmationVariants(t *testing.T) {
	if NeedsConfirmation(nil) || NeedsConfirmation([]Action{{Subsystem: "dns"}}) {
		t.Fatal("safe or empty plan requires confirmation")
	}
	if !NeedsConfirmation([]Action{{Subsystem: "routing"}}) || !NeedsConfirmation([]Action{{Subsystem: "dns", Disruptive: true}}) {
		t.Fatal("connectivity/disruptive plan skipped confirmation")
	}
}

func TestBridgeTopologyChangeDetection(t *testing.T) {
	old := validConfig("old")
	next := validConfig("new")
	if bridgeTopologyChanged(old, next) {
		t.Fatal("unrelated config change was treated as bridge topology change")
	}
	next.Interfaces = append(next.Interfaces, config.Interface{ID: "br-lan", Name: "br-lan", Type: "bridge", Enabled: true})
	if !bridgeTopologyChanged(old, next) {
		t.Fatal("new bridge was not detected")
	}
	old.Interfaces = append(old.Interfaces, next.Interfaces[len(next.Interfaces)-1])
	if bridgeTopologyChanged(old, next) {
		t.Fatal("identical bridge topology was treated as changed")
	}
	next.Interfaces[len(next.Interfaces)-1].Members = []string{"lan0"}
	if !bridgeTopologyChanged(old, next) {
		t.Fatal("bridge member change was not detected")
	}
}
