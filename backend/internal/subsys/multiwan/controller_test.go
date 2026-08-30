package multiwan

import (
	"context"
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
	c.record(context.Background(), w, "wan0", state, false)
	if r.route == "" {
		t.Fatal("маршрут снят раньше порога")
	}
	c.record(context.Background(), w, "wan0", state, false)
	if r.route != "" || !state.Down {
		t.Fatal("маршрут не снят после порога")
	}
	c.record(context.Background(), w, "wan0", state, true)
	if r.route != "" {
		t.Fatal("маршрут восстановлен раньше порога")
	}
	c.record(context.Background(), w, "wan0", state, true)
	if r.route == "" || state.Down {
		t.Fatal("маршрут не восстановлен")
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
