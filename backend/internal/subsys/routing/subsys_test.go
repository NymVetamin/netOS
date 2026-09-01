package routing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type recordedCommand struct {
	name string
	args []string
}
type runnerResponse struct {
	out string
	err error
}
type recordingRunner struct {
	commands  []recordedCommand
	responses map[string]runnerResponse
}

func commandKey(name string, args ...string) string { return name + " " + strings.Join(args, " ") }
func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, recordedCommand{name, append([]string(nil), args...)})
	if response, ok := r.responses[commandKey(name, args...)]; ok {
		return response.out, response.err
	}
	return "", nil
}
func (r *recordingRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestMetadataAndPlan(t *testing.T) {
	s := New(&recordingRunner{})
	if s.Name() != "routing" {
		t.Fatalf("Name() = %q", s.Name())
	}
	old, next := config.Default(), config.Default()
	next.Routing.Tables = []config.RouteTable{{Name: "qa", Number: 200}}
	next.Routing.Static = []config.StaticRoute{{Enabled: true, Destination: "10.0.0.0/8", Type: "blackhole"}}
	next.Routing.Rules = []config.RouteRule{{Enabled: true, Priority: 20100, Table: "qa"}}
	actions, err := s.Plan(nil, next)
	if err != nil || len(actions) != 2 || actions[0].Kind != "create" || actions[1].Kind != "create" {
		t.Fatalf("initial Plan = %#v, %v", actions, err)
	}
	actions, err = s.Plan(old, next)
	if err != nil || len(actions) != 3 || !actions[2].Disruptive {
		t.Fatalf("update Plan = %#v, %v", actions, err)
	}
	actions, err = s.Plan(next, next)
	if err != nil || len(actions) != 0 {
		t.Fatalf("unchanged Plan = %#v, %v", actions, err)
	}
}

func TestApplyWritesRegistriesAndReconciles(t *testing.T) {
	tmp := t.TempDir()
	oldTables, oldProtos := rtTablesPath, rtProtosPath
	rtTablesPath, rtProtosPath = filepath.Join(tmp, "rt_tables"), filepath.Join(tmp, "rt_protos")
	t.Cleanup(func() { rtTablesPath, rtProtosPath = oldTables, oldProtos })
	runner, cfg := &recordingRunner{}, config.Default()
	cfg.Routing.Tables = []config.RouteTable{{Name: "qa", Number: 200}}
	if err := New(runner).Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	assertFile(t, rtTablesPath, "200\tqa", 0o644)
	assertFile(t, rtProtosPath, fmt.Sprintf("%d\tnetos", config.RouteProto), 0o644)
	if len(runner.commands) != 3 {
		t.Fatalf("commands = %#v", runner.commands)
	}
}

func TestApplyStopsAtEveryFailedStage(t *testing.T) {
	oldTables, oldProtos := rtTablesPath, rtProtosPath
	t.Cleanup(func() { rtTablesPath, rtProtosPath = oldTables, oldProtos })
	for _, tc := range []struct {
		name      string
		badProtos bool
		badTables bool
		responses map[string]runnerResponse
	}{
		{name: "protos", badProtos: true},
		{name: "tables", badTables: true},
		{name: "routes", responses: map[string]runnerResponse{"ip -4 route show table all proto static": {err: errors.New("routes")}}},
		{name: "rules", responses: map[string]runnerResponse{"ip -4 rule show": {err: errors.New("rules")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			rtProtosPath, rtTablesPath = filepath.Join(tmp, "protos"), filepath.Join(tmp, "tables")
			if tc.badProtos {
				rtProtosPath = tmp // atomic rename onto a directory must fail.
			}
			if tc.badTables {
				rtTablesPath = tmp
			}
			err := New(&recordingRunner{responses: tc.responses}).Apply(context.Background(), config.Default())
			if err == nil {
				t.Fatal("expected Apply error")
			}
		})
	}
}

func assertFile(t *testing.T, path, contains string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), contains) {
		t.Fatalf("%s: %q, %v", path, b, err)
	}
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
		t.Fatalf("mode %s = %v, %v", path, info.Mode().Perm(), err)
	}
}

func TestApplyRoutesDualStackAndStaleCleanup(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{
		"ip -4 route show table all proto static": {out: "10.99.0.0/16 via 192.0.2.1 dev eth0 proto static\n"},
		"ip -6 route show table all proto static": {out: "unreachable 2001:db8:dead::/48 metric 9 proto static\n"},
	}}
	cfg := config.Default()
	cfg.Routing.Static = []config.StaticRoute{
		{Enabled: true, Destination: "10.20.0.0/16", Gateway: "192.0.2.1", Metric: 5, Table: "main"},
		{Enabled: true, Destination: "2001:db8:20::/48", Type: "blackhole", Table: "200"},
		{Enabled: false, Destination: "203.0.113.0/24", Interface: "eth0"},
	}
	if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{
		"ip -4 route del 10.99.0.0/16 via 192.0.2.1 dev eth0 proto static",
		"ip -6 route del unreachable 2001:db8:dead::/48 metric 9 proto static",
		"ip -4 route replace 10.20.0.0/16 via 192.0.2.1 metric 5 table main proto static",
		"ip -6 route replace blackhole 2001:db8:20::/48 table 200 proto static",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestApplyRoutesKeepsConfiguredRouteAndInfersDefaultFamily(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{"ip -6 route show table all proto static": {out: "default via 2001:db8::1 dev eth0 proto static\n"}}}
	cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: "default", Gateway: "2001:db8::1", Interface: "eth0"})
	if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	if strings.Contains(got, "route del default") || !strings.Contains(got, "ip -6 route replace default") {
		t.Fatalf("unexpected commands:\n%s", got)
	}
}

func TestApplyRoutesReturnsEveryCommandFailure(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]runnerResponse
		cfg       *config.Config
	}{
		{"show4", map[string]runnerResponse{"ip -4 route show table all proto static": {err: errors.New("show4")}}, config.Default()},
		{"show6", map[string]runnerResponse{"ip -6 route show table all proto static": {err: errors.New("show6")}}, config.Default()},
		{"delete", map[string]runnerResponse{"ip -4 route show table all proto static": {out: "10.0.0.0/8 proto static\n"}, "ip -4 route del 10.0.0.0/8 proto static": {err: errors.New("delete")}}, config.Default()},
		{"replace", map[string]runnerResponse{"ip -4 route replace blackhole 10.0.0.0/8 proto static": {err: errors.New("replace")}}, routeConfig(config.StaticRoute{Enabled: true, Destination: "10.0.0.0/8", Type: "blackhole"})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := New(&recordingRunner{responses: tc.responses}).applyRoutes(context.Background(), tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func routeConfig(route config.StaticRoute) *config.Config {
	cfg := config.Default()
	cfg.Routing.Static = []config.StaticRoute{route}
	return cfg
}

func TestRouteKeysAndParsing(t *testing.T) {
	if routeFamily(config.StaticRoute{Destination: "192.0.2.0/24"}) != "-4" || routeFamily(config.StaticRoute{Destination: "default", Gateway: "2001:db8::1"}) != "-6" {
		t.Fatal("route family inference failed")
	}
	want := routeKey("", "10.0.0.0/8", "unicast", "192.0.2.1", "eth0", 7)
	got := routeLineKey("10.0.0.0/8 via 192.0.2.1 dev eth0 metric 7 table main proto static")
	if got != want {
		t.Fatalf("routeLineKey = %q, want %q", got, want)
	}
	if routeLineKey("") != "" {
		t.Fatal("empty route line must have empty key")
	}
	blackhole := config.StaticRoute{Destination: "10.0.0.0/8", Type: "blackhole", Table: "200"}
	if staticRouteKey(blackhole) != routeLineKey("blackhole 10.0.0.0/8 table 200 proto static") {
		t.Fatal("blackhole keys differ")
	}
}

func TestApplyRulesReconcilesSelectorsAndPropagatesFailures(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{"ip -4 rule show": {out: "0: from all lookup local\n20111: from all lookup old\n32766: from all lookup main\n"}}}
	cfg := config.Default()
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Name: "qa", Priority: 20222, From: "192.0.2.0/24", To: "198.51.100.0/24", FwMark: "0x10/0xff", Interface: "eth0", Table: "qa"}}
	if err := New(runner).applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{"ip -4 rule del priority 20111", "ip -4 rule add from 192.0.2.0/24 to 198.51.100.0/24 fwmark 0x10/0xff iif eth0 priority 20222 lookup qa"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	tests := []struct {
		name      string
		responses map[string]runnerResponse
	}{
		{"show", map[string]runnerResponse{"ip -4 rule show": {err: errors.New("show")}}},
		{"delete", map[string]runnerResponse{"ip -4 rule show": {out: "20111: from all lookup old\n"}, "ip -4 rule del priority 20111": {err: errors.New("delete")}}},
		{"add", map[string]runnerResponse{"ip -4 rule add from 192.0.2.0/24 to 198.51.100.0/24 fwmark 0x10/0xff iif eth0 priority 20222 lookup qa": {err: errors.New("add")}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := New(&recordingRunner{responses: tc.responses}).applyRules(context.Background(), cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestApplyRulesDefaultsAndFiltersDisabled(t *testing.T) {
	runner, cfg := &recordingRunner{}, config.Default()
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Name: "fallback", Priority: 1, Table: "main"}, {Enabled: false, Priority: 20200, Table: "ignored"}, {Enabled: true, Priority: 20300}}
	if err := New(runner).applyRules(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	if !strings.Contains(got, "from all priority 20100 lookup main") || strings.Contains(got, "ignored") {
		t.Fatalf("unexpected commands:\n%s", got)
	}
}

func TestHealthRequiresPriorityAndExactTableOnSameLine(t *testing.T) {
	cfg := config.Default()
	cfg.Routing.Rules = []config.RouteRule{{Enabled: true, Priority: 20100, Table: "qa"}}
	tests := []struct {
		name, out string
		err       error
		ok        bool
	}{
		{"exact", "20100: from all lookup qa\n", nil, true}, {"table keyword", "20100: from all table qa\n", nil, true},
		{"wrong priority", "20101: from all lookup qa\n", nil, false}, {"substring", "20100: from all lookup qa-old\n", nil, false},
		{"split lines", "20100: from all lookup old\n20101: from all lookup qa\n", nil, false}, {"runner", "", errors.New("rules unavailable"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{responses: map[string]runnerResponse{"ip -4 rule show": {out: tc.out, err: tc.err}}}
			err := New(runner).Health(context.Background(), cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("Health error = %v", err)
			}
		})
	}
	if err := New(&recordingRunner{}).Health(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
}

func TestLeadingPriorityAndEnabledHelpers(t *testing.T) {
	for input, want := range map[string]int{" 20100: from all": 20100, "x: bad": -1, "no colon": -1, ": empty": -1} {
		if got := leadingPriority(input); got != want {
			t.Fatalf("leadingPriority(%q) = %d, want %d", input, got, want)
		}
	}
	cfg := config.Default()
	cfg.Routing.Static = []config.StaticRoute{{ID: "on", Enabled: true}, {ID: "off"}}
	cfg.Routing.Rules = []config.RouteRule{{ID: "on", Enabled: true, Table: "main"}, {ID: "empty", Enabled: true}, {ID: "off", Table: "main"}}
	if got := enabledRoutes(cfg); !reflect.DeepEqual(got, []config.StaticRoute{cfg.Routing.Static[0]}) {
		t.Fatalf("enabledRoutes = %#v", got)
	}
	if got := enabledRules(cfg); !reflect.DeepEqual(got, []config.RouteRule{cfg.Routing.Rules[0]}) {
		t.Fatalf("enabledRules = %#v", got)
	}
}

func commandStrings(commands []recordedCommand) string {
	var out []string
	for _, command := range commands {
		out = append(out, commandKey(command.name, command.args...))
	}
	return strings.Join(out, "\n")
}
