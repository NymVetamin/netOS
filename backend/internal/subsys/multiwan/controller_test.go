package multiwan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	route    string
	commands []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	if strings.Contains(cmd, "route show default dev wan0") {
		return r.route, nil
	}
	if strings.Contains(cmd, "route del default") {
		r.route = ""
	}
	if strings.Contains(cmd, "route replace default") {
		r.route = "default via 192.0.2.1 dev wan0 proto dhcp metric 100\n"
	}
	return "", nil
}
func (r *fakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type testLogger struct{}

func (testLogger) Infof(string, ...any) {}
func (testLogger) Warnf(string, ...any) {}

func TestFailoverSuppressesAndRestoresRouteAtThresholds(t *testing.T) {
	r := &fakeRunner{route: "default via 192.0.2.1 dev wan0 proto dhcp metric 100\n"}
	c := New(r, t.TempDir(), testLogger{})
	c.suppressed = map[string]string{}
	w := config.WAN{ID: "primary", Name: "Primary", Probe: config.Probe{FailThreshold: 2, RiseThreshold: 2}}
	state := &linkState{}
	c.record(context.Background(), w, "wan0", state, false, true)
	if r.route == "" {
		t.Fatal("маршрут снят раньше порога")
	}
	c.record(context.Background(), w, "wan0", state, false, true)
	if r.route != "" || !state.Down {
		t.Fatal("маршрут не снят после порога")
	}
	c.record(context.Background(), w, "wan0", state, true, true)
	if r.route != "" {
		t.Fatal("маршрут восстановлен раньше порога")
	}
	c.record(context.Background(), w, "wan0", state, true, true)
	if r.route == "" || state.Down {
		t.Fatal("маршрут не восстановлен")
	}
}

func TestFailoverRestoresRouteLostByCarrierTransition(t *testing.T) {
	r := &fakeRunner{}
	c := New(r, t.TempDir(), testLogger{})
	c.suppressed = map[string]string{}
	c.knownRoutes = map[string]string{
		"primary": "default via 192.0.2.1 dev wan0 proto dhcp metric 100",
	}
	w := config.WAN{ID: "primary", Name: "Primary", Probe: config.Probe{FailThreshold: 1, RiseThreshold: 2}}
	state := &linkState{}
	if !c.record(context.Background(), w, "wan0", state, false, true) {
		t.Fatal("carrier loss without a live route was not recorded")
	}
	if !state.Down || c.suppressed[w.ID] == "" || r.route != "" {
		t.Fatalf("lost route state=%+v suppressed=%q live=%q", state, c.suppressed[w.ID], r.route)
	}
	c.record(context.Background(), w, "wan0", state, true, true)
	if r.route != "" {
		t.Fatal("route restored before rise threshold")
	}
	c.record(context.Background(), w, "wan0", state, true, true)
	if state.Down || r.route == "" || len(c.suppressed) != 0 {
		t.Fatalf("route not restored: state=%+v live=%q suppressed=%v", state, r.route, c.suppressed)
	}
}

func TestProbeRouteUsesLastKnownRouteAfterCarrierReturns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "multiwan-balance.json"), []byte("[1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	c := New(r, dir, testLogger{})
	c.knownRoutes = map[string]string{
		"primary": "default via 192.0.2.1 dev wan0 proto netos metric 100",
	}
	w := config.WAN{ID: "primary", Index: 1}
	if err := c.refreshProbeRoute(context.Background(), w, "wan0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.commands, "\n"), "route replace default via 192.0.2.1 dev wan0 proto netos table 3001") {
		t.Fatalf("known route was not restored to the probe table: %v", r.commands)
	}
}

func TestProbeRouteRepairFailureStillRecordsCarrierLoss(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "multiwan-balance.json"), []byte("[1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &responseRunner{respond: func(command string) (string, error) {
		if strings.Contains(command, "route replace") && strings.Contains(command, "table 3001") {
			return "", errors.New("invalid gateway while carrier is down")
		}
		return "", nil
	}}
	c := New(r, dir, testLogger{})
	c.states = map[string]*linkState{}
	c.suppressed = map[string]string{}
	c.knownRoutes = map[string]string{
		"primary": "default via 192.0.2.1 dev wan0 proto netos metric 100",
	}
	c.Probe = func(context.Context, config.WAN, string) bool { return false }
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "failover"
	cfg.Interfaces = []config.Interface{{ID: "if0", Name: "wan0"}}
	cfg.WANs = []config.WAN{{
		ID: "primary", Index: 1, Name: "Primary", Interface: "if0", Enabled: true,
		Probe: config.Probe{Enabled: true, FailThreshold: 1},
	}}
	c.tick(context.Background(), cfg)
	if state := c.states["primary"]; state == nil || !state.Down || c.suppressed["primary"] == "" {
		t.Fatalf("carrier loss was skipped after probe-route failure: state=%+v suppressed=%v", state, c.suppressed)
	}
}

func TestApplyRestoresRouteAfterDaemonCrash(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "multiwan-suppressed.json")
	if err := os.WriteFile(state, []byte("{\"primary\":\"default via 192.0.2.1 dev wan0 metric 100\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	c := New(r, dir, testLogger{})
	if err := c.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.commands, "\n"), "route replace default via 192.0.2.1") {
		t.Fatal(r.commands)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("файл подавленных маршрутов не удалён")
	}
}
