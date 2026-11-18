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
	protos, err := os.ReadFile(rtProtosPath)
	if err != nil || strings.Contains(string(protos), "netos-static") {
		t.Fatalf("legacy static protocol was registered: %q, %v", protos, err)
	}
	if len(runner.commands) != 5 {
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
		{name: "routes", responses: map[string]runnerResponse{"ip -4 route show table all proto 202": {err: errors.New("routes")}}},
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
		"ip -4 route show table all proto 202": {out: "10.99.0.0/16 via 192.0.2.1 dev eth0 proto 202\n"},
		"ip -6 route show table all proto 202": {out: "unreachable 2001:db8:dead::/48 metric 9 proto 202\n"},
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
		"ip -4 route del 10.99.0.0/16 via 192.0.2.1 dev eth0 proto 202",
		"ip -6 route del unreachable 2001:db8:dead::/48 metric 9 proto 202",
		"ip -4 route replace 10.20.0.0/16 via 192.0.2.1 metric 5 table main proto static",
		"ip -6 route replace blackhole 2001:db8:20::/48 table 200 proto static",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestApplyRoutesDeletesUnconfiguredStaticRoutes(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{
		"ip -4 route show table all proto static": {out: "203.0.113.251 dev eth2 proto static\n198.51.100.0/24 dev eth3 table 200 proto static\n"},
		"ip -6 route show table all proto static": {out: "2001:db8:dead::/48 dev eth2 table 200 proto static\n"},
	}}
	if err := New(runner).applyRoutes(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{
		"ip -4 route del 203.0.113.251 dev eth2 proto static",
		"ip -4 route del 198.51.100.0/24 dev eth3 table 200 proto static",
		"ip -6 route del 2001:db8:dead::/48 dev eth2 table 200 proto static",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	for _, command := range runner.commands {
		args := strings.Join(command.args, " ")
		if strings.Contains(args, "proto 201") {
			t.Fatalf("uplink route was queried: %v", command)
		}
	}
}

func TestApplyRoutesPreservesConfiguredStaticRoute(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{
		"ip -4 route show table all proto static": {out: "203.0.113.0/24 via 192.0.2.1 dev eth0 proto static\n"},
	}}
	cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: "203.0.113.0/24", Gateway: "192.0.2.1", Interface: "eth0"})
	if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	if strings.Contains(got, "route del 203.0.113.0/24") || strings.Contains(got, "route replace") {
		t.Fatalf("configured static route should remain unchanged:\n%s", got)
	}
}

func TestApplyRoutesMigratesLegacyProto202(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{
		"ip -4 route show table all proto 202": {out: "203.0.113.0/24 dev lo proto 202\n"},
	}}
	cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: "203.0.113.0/24", Interface: "lo"})
	if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	if strings.Contains(got, "route del 203.0.113.0/24") || !strings.Contains(got, "route replace 203.0.113.0/24 dev lo proto static") {
		t.Fatalf("legacy route should migrate in place:\n%s", got)
	}
}

func TestApplyRoutesKeepsConfiguredHostRoute(t *testing.T) {
	for _, tc := range []struct {
		family  string
		address string
		prefix  string
	}{
		{"-4", "192.0.2.77", "192.0.2.77/32"},
		{"-6", "2001:db8::77", "2001:db8::77/128"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			show := "ip " + tc.family + " route show table all proto static"
			runner := &recordingRunner{responses: map[string]runnerResponse{
				show: {out: tc.address + " dev lo proto static\n"},
			}}
			cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: tc.prefix, Interface: "lo"})
			if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			got := commandStrings(runner.commands)
			if strings.Contains(got, "route del "+tc.address) || strings.Contains(got, "route replace") {
				t.Fatalf("configured host route should remain unchanged:\n%s", got)
			}
		})
	}
}

func TestApplyRoutesKeepsConfiguredRouteAndInfersDefaultFamily(t *testing.T) {
	runner := &recordingRunner{responses: map[string]runnerResponse{"ip -6 route show table all proto static": {out: "default via 2001:db8::1 dev eth0 proto static\n"}}}
	cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: "default", Gateway: "2001:db8::1", Interface: "eth0"})
	if err := New(runner).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got := commandStrings(runner.commands)
	if strings.Contains(got, "route del default") || strings.Contains(got, "route replace") {
		t.Fatalf("unexpected commands:\n%s", got)
	}
}

func TestApplyRoutesReturnsEveryCommandFailure(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]runnerResponse
		cfg       *config.Config
	}{
		{"show4", map[string]runnerResponse{"ip -4 route show table all proto 202": {err: errors.New("show4")}}, config.Default()},
		{"show6", map[string]runnerResponse{"ip -6 route show table all proto 202": {err: errors.New("show6")}}, config.Default()},
		{"delete", map[string]runnerResponse{"ip -4 route show table all proto 202": {out: "10.0.0.0/8 proto 202\n"}, "ip -4 route del 10.0.0.0/8 proto 202": {err: errors.New("delete")}}, config.Default()},
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

// Benchmark the whole routing pass against an unchanged kernel snapshot.
func BenchmarkTunnelRouteReconcile(b *testing.B) {
	for _, n := range []int{32, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := config.Default()
			cfg.Channels = append(cfg.Channels, config.Channel{Index: 1, Type: "wireguard", Enabled: true})
			var live strings.Builder
			for i := 0; i < n; i++ {
				dest := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
				fmt.Fprintf(&live, "%s dev wg-ch1 scope link\n", dest)
				cfg.Routing.Static = append(cfg.Routing.Static, config.StaticRoute{Destination: dest, Interface: "wg-ch1", Enabled: true})
			}
			r := &recordingRunner{responses: map[string]runnerResponse{"ip -4 route show table all proto static": {out: live.String()}}}
			s, late := New(r), &TunnelRoutes{Runner: r}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.commands = r.commands[:0]
				ctx := context.Background()
				if err := s.applyRoutes(ctx, cfg); err != nil {
					b.Fatal(err)
				}
				if err := late.Apply(ctx, cfg); err != nil {
					b.Fatal(err)
				}
				if err := late.Health(ctx, cfg); err != nil {
					b.Fatal(err)
				}
				if len(r.commands) != 6 {
					b.Fatalf("unchanged routes issued %d commands", len(r.commands))
				}
			}
			b.ReportMetric(6, "commands/op")
		})
	}
}

func TestDisabledOwnerOnlySuspendsItsUnicastRoutes(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{
		{Index: 1, Type: "wireguard", Enabled: false},
		{Index: 2, Type: "wireguard", WireGuardPeer: &config.WireGuardPeerChannel{}},
	}
	cfg.VPNServers = []config.VPNServer{{Index: 1, Type: "wireguard", Enabled: true}}
	for _, r := range []config.StaticRoute{
		{Interface: "wg-ch1", Type: "unicast"}, {Interface: "wg-srv1"}, {Interface: "unknown"},
		{Interface: "wg-ch1", Type: "blackhole"},
	} {
		r.Enabled = true
		cfg.Routing.Static = append(cfg.Routing.Static, r)
	}
	base, tunnels := splitRoutes(cfg, true)
	if !reflect.DeepEqual(base, cfg.Routing.Static[2:]) || !reflect.DeepEqual(tunnels, cfg.Routing.Static[1:2]) {
		t.Fatalf("base %v tunnels %v", base, tunnels)
	}
	off := *cfg
	off.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	off.VPNServers[0].Enabled = false
	actions, err := New(&recordingRunner{}).Plan(cfg, &off)
	if err != nil || len(actions) != 1 || actions[0].Confirmation == "safe" {
		t.Fatalf("route suspension plan: %+v, %v", actions, err)
	}
	r := &recordingRunner{}
	late := &TunnelRoutes{Runner: r}
	if err := late.Apply(context.Background(), &off); err != nil {
		t.Fatal(err)
	}
	if err := late.Health(context.Background(), &off); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != 0 {
		t.Fatalf("inactive tunnels issued commands: %+v", r.commands)
	}
}
