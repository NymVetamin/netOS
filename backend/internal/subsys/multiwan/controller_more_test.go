package multiwan

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type responseRunner struct {
	commands []string
	respond  func(string) (string, error)
}

type balanceStateRunner struct {
	routes   map[string]string
	main     map[string]string
	rules    map[string]string
	failOnce string
	failed   bool
}

func (r *balanceStateRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if r.failOnce != "" && !r.failed && strings.Contains(command, r.failOnce) {
		r.failed = true
		return "", errors.New("injected failure")
	}
	if name != "ip" {
		return "", nil
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(joined, "-4 route show default dev "):
		return r.main[args[len(args)-1]], nil
	case strings.HasPrefix(joined, "-4 route show table "):
		return r.routes[args[len(args)-1]], nil
	case strings.HasPrefix(joined, "-4 route flush table "):
		r.routes[args[len(args)-1]] = ""
	case strings.HasPrefix(joined, "-4 route replace "):
		table := ""
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "table" {
				table = args[i+1]
				break
			}
		}
		if table != "" {
			line := strings.Join(args[3:], " ")
			line = strings.TrimSpace(strings.Split(line, " table ")[0])
			if strings.HasPrefix(line, "default") {
				var kept []string
				for _, current := range strings.Split(r.routes[table], "\n") {
					if current != "" && !strings.HasPrefix(current, "default") {
						kept = append(kept, current)
					}
				}
				kept = append([]string{line}, kept...)
				r.routes[table] = strings.Join(kept, "\n") + "\n"
			} else if strings.HasPrefix(line, "blackhole default") && !strings.Contains(r.routes[table], "blackhole default") {
				r.routes[table] += line + "\n"
			}
		}
	case joined == "-4 rule show":
		var priorities []string
		for priority := range r.rules {
			priorities = append(priorities, priority)
		}
		sort.Strings(priorities)
		var lines []string
		for _, priority := range priorities {
			lines = append(lines, r.rules[priority])
		}
		return strings.Join(lines, "\n") + "\n", nil
	case strings.HasPrefix(joined, "-4 rule del priority "):
		delete(r.rules, args[len(args)-1])
	case strings.HasPrefix(joined, "-4 rule add "):
		priority, mark, table := "", "", ""
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "priority":
				priority = args[i+1]
			case "fwmark":
				mark = args[i+1]
			case "lookup", "table":
				table = args[i+1]
			}
		}
		if priority != "" {
			r.rules[priority] = priority + ": from all fwmark " + mark + " lookup " + table
		}
	}
	return "", nil
}

func (r *balanceStateRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *responseRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.respond != nil {
		return r.respond(command)
	}
	return "", nil
}

func (r *responseRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type captureLogger struct{ messages []string }

func (l *captureLogger) Infof(format string, _ ...any) { l.messages = append(l.messages, format) }
func (l *captureLogger) Warnf(format string, _ ...any) { l.messages = append(l.messages, format) }

func TestMetadataPlanAndInterfaceNames(t *testing.T) {
	wan := config.WAN{ID: "uplink", Index: 7}
	if Table(wan) != 3007 || Mark(wan) != 0x3007 || Priority(wan) != 30007 {
		t.Fatalf("identifiers table=%d mark=%x priority=%d", Table(wan), Mark(wan), Priority(wan))
	}
	c := New(&responseRunner{}, t.TempDir(), &captureLogger{})
	if c.Name() != "multiwan" || c.Health(context.Background(), config.Default()) != nil {
		t.Fatal("unexpected subsystem metadata or health")
	}
	enabled := config.Default()
	enabled.MultiWAN.Enabled = true
	enabled.MultiWAN.Mode = "failover"
	actions, err := c.Plan(nil, enabled)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" || !actions[0].Disruptive {
		t.Fatalf("enable plan=%+v err=%v", actions, err)
	}
	disabled := config.Default()
	actions, err = c.Plan(enabled, disabled)
	if err != nil || len(actions) != 1 || actions[0].Kind != "delete" {
		t.Fatalf("disable plan=%+v err=%v", actions, err)
	}
	if actions, err := c.Plan(disabled, config.Default()); err != nil || len(actions) != 0 {
		t.Fatalf("unchanged plan=%+v err=%v", actions, err)
	}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "physical", Name: "eth9"}}
	if got := interfaceName(cfg, config.WAN{Interface: "physical", Proto: "static"}); got != "eth9" {
		t.Fatalf("physical interface=%q", got)
	}
	for _, proto := range []string{"pppoe", "l2tp"} {
		if got := interfaceName(cfg, config.WAN{ID: "wan-a", Proto: proto}); got != "ppp-wan-a" {
			t.Fatalf("%s interface=%q", proto, got)
		}
	}
}

func TestProbeFamiliesProtocolsTargetsAndTimeouts(t *testing.T) {
	r := &responseRunner{respond: func(command string) (string, error) {
		if strings.Contains(command, "198.51.100.2") || strings.Contains(command, "https://ok.example") {
			return "", nil
		}
		return "", errors.New("unreachable")
	}}
	c := New(r, t.TempDir(), &captureLogger{})
	ctx := context.Background()
	if !c.probe(ctx, config.WAN{Probe: config.Probe{Type: "icmp", Targets: []string{"198.51.100.1", "198.51.100.2"}}}, "wan0") {
		t.Fatal("second healthy ICMP target was ignored")
	}
	if !strings.Contains(strings.Join(r.commands, "\n"), "ping -4 -I wan0 -c 1 -W 3 198.51.100.2") {
		t.Fatalf("IPv4 probe commands=%v", r.commands)
	}
	r.commands = nil
	if c.probe(ctx, config.WAN{Probe: config.Probe{Type: "icmp", Targets: []string{"2001:db8::2"}, Timeout: 7}}, "wan0") {
		t.Fatal("failed IPv6 ICMP target reported healthy")
	}
	if !strings.Contains(strings.Join(r.commands, "\n"), "ping -6 -I wan0 -c 1 -W 7 2001:db8::2") {
		t.Fatalf("IPv6 probe commands=%v", r.commands)
	}
	r.commands = nil
	if !c.probe(ctx, config.WAN{Probe: config.Probe{Type: "http", Targets: []string{"https://ok.example"}, Timeout: 4}}, "wan0") {
		t.Fatal("healthy HTTP target reported down")
	}
	if !strings.Contains(r.commands[0], "curl --interface wan0 --fail --silent --max-time 4 https://ok.example") {
		t.Fatalf("HTTP probe command=%v", r.commands)
	}
	if c.probe(ctx, config.WAN{Probe: config.Probe{Type: "tcp", Targets: []string{"bad"}}}, "wan0") {
		t.Fatal("only malformed targets reported healthy")
	}
}

func TestTCPProbeOnlyRequiresHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	c := New(&responseRunner{}, t.TempDir(), &captureLogger{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wan := config.WAN{Probe: config.Probe{Type: "tcp", Targets: []string{"invalid", listener.Addr().String()}, Timeout: 1}}
	if !c.probe(ctx, wan, "") {
		t.Fatal("silent TCP listener was reported down")
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-ctx.Done():
		t.Fatal("probe did not reach listener")
	}
}

func TestSuppressionIsRolledBackWhenStateCannotBeSaved(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{route: "default via 192.0.2.1 dev wan0 metric 100\n"}
	logger := &captureLogger{}
	c := New(r, blocker, logger)
	c.suppressed = map[string]string{}
	state := &linkState{}
	wan := config.WAN{ID: "primary", Name: "Primary", Probe: config.Probe{FailThreshold: 1}}
	if changed := c.record(context.Background(), wan, "wan0", state, false, true); changed {
		t.Fatal("non-durable suppression reported as successful")
	}
	if r.route == "" || state.Down || len(c.suppressed) != 0 {
		t.Fatalf("unsafe suppression remains: route=%q state=%+v suppressed=%v", r.route, state, c.suppressed)
	}
	if len(logger.messages) == 0 {
		t.Fatal("persistence failure was not logged")
	}
}

func balanceConfig() *config.Config {
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "balance"
	cfg.Interfaces = []config.Interface{{ID: "if0", Name: "wan0"}, {ID: "if1", Name: "wan1"}}
	cfg.WANs = []config.WAN{
		{ID: "a", Index: 1, Name: "A", Interface: "if0", Enabled: true, Proto: "static"},
		{ID: "b", Index: 2, Name: "B", Interface: "if1", Enabled: true, Proto: "static"},
	}
	return cfg
}

func TestBalanceBuildsTablesRepairsCrossMatchedRulesAndCleansOldState(t *testing.T) {
	dir := t.TempDir()
	r := &responseRunner{respond: func(command string) (string, error) {
		switch {
		case strings.Contains(command, "route show default dev wan0"):
			return "default via 192.0.2.1 metric 100\n", nil
		case strings.Contains(command, "route show default dev wan1"):
			return "default via 198.51.100.1 dev wan1 metric 200\n", nil
		case strings.Contains(command, "rule show"):
			return "30001: from all fwmark 0x3002 lookup 3001\n30002: from all fwmark 0x3001 lookup 3002\n", nil
		default:
			return "", nil
		}
	}}
	c := New(r, dir, &captureLogger{})
	if err := c.reconcileBalance(context.Background(), balanceConfig()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.commands, "\n")
	for _, want := range []string{
		"route replace default via 192.0.2.1 metric 100 dev wan0 table 3001",
		"route replace blackhole default metric 32767 table 3001",
		"rule add fwmark 0x3001 priority 30001 lookup 3001",
		"rule add fwmark 0x3002 priority 30002 lookup 3002",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in commands:\n%s", want, joined)
		}
	}
	owned := filepath.Join(dir, "multiwan-balance.json")
	data, err := os.ReadFile(owned)
	if err != nil || string(data) != "[1,2]\n" {
		t.Fatalf("owned state=%q err=%v", data, err)
	}

	r.commands = nil
	if err := c.reconcileBalance(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(r.commands, "\n")
	for _, want := range []string{"rule del priority 30001", "route flush table 3001", "rule del priority 30002", "route flush table 3002"} {
		if !strings.Contains(joined, want) {
			t.Errorf("cleanup missing %q in %s", want, joined)
		}
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("owned state remains: %v", err)
	}
}

func TestBalancePropagatesRouteDiscoveryFailure(t *testing.T) {
	r := &responseRunner{respond: func(command string) (string, error) {
		if strings.Contains(command, "route show default") {
			return "", errors.New("ip failed")
		}
		return "", nil
	}}
	c := New(r, t.TempDir(), &captureLogger{})
	if err := c.reconcileBalance(context.Background(), balanceConfig()); err == nil || !strings.Contains(err.Error(), "A") {
		t.Fatalf("route discovery error=%v", err)
	}
}

func TestTickRestoresNoLongerWantedRouteAndRunRestoresOnShutdown(t *testing.T) {
	r := &fakeRunner{}
	c := New(r, t.TempDir(), &captureLogger{})
	line := "default via 192.0.2.1 dev wan0 metric 100"
	c.suppressed = map[string]string{"old": line}
	c.states = map[string]*linkState{"old": {Down: true}}
	c.tick(context.Background(), config.Default())
	if len(c.suppressed) != 0 || len(c.states) != 0 || r.route == "" {
		t.Fatalf("tick did not restore stale route: suppressed=%v states=%v route=%q", c.suppressed, c.states, r.route)
	}

	c.suppressed = map[string]string{"shutdown": line}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Run(ctx, func() *config.Config { return config.Default() })
	if len(c.suppressed) != 0 {
		t.Fatalf("shutdown did not restore routes: %v", c.suppressed)
	}

	r.commands = nil
	c.pausedUntil = time.Now().Add(time.Minute)
	c.tick(context.Background(), balanceConfig())
	if len(r.commands) != 0 {
		t.Fatalf("paused monitor executed commands: %v", r.commands)
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "multiwan-suppressed.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(&responseRunner{}, dir, &captureLogger{})
	if err := c.Apply(context.Background(), config.Default()); err == nil {
		t.Fatal("corrupt persistent state was accepted")
	}
}

func TestHasBalanceRuleRequiresPriorityAndMarkOnSameLine(t *testing.T) {
	crossed := "30001: from all fwmark 0x3002 lookup 3001\n30002: from all fwmark 0x3001 lookup 3002"
	if hasBalanceRule(crossed, "30001", "0x3001", "3001") {
		t.Fatal("priority and mark from different rules were combined")
	}
	if !hasBalanceRule("30001: from all fwmark 0x3001/0xffffffff lookup 3001", "30001", "0x3001", "3001") {
		t.Fatal("valid masked fwmark rule was not recognized")
	}
	if hasBalanceRule("30001: from all fwmark 0x3001 lookup 3999", "30001", "0x3001", "3001") {
		t.Fatal("rule with a wrong lookup table was accepted")
	}
}

func TestHealthAndPlanDetectBalanceDrift(t *testing.T) {
	dir := t.TempDir()
	cfg := balanceConfig()
	owned := filepath.Join(dir, "multiwan-balance.json")
	if err := os.WriteFile(owned, []byte("[1,2]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := "30001: from all fwmark 0x3001 lookup 3001\n30002: from all fwmark 0x3002 lookup 3002\n"
	r := &responseRunner{respond: func(command string) (string, error) {
		switch {
		case strings.Contains(command, "ip -4 rule show"):
			return rules, nil
		case strings.Contains(command, "route show table 3001"), strings.Contains(command, "route show table 3002"):
			return "default via 192.0.2.1\nblackhole default metric 32767\n", nil
		default:
			return "", nil
		}
	}}
	c := New(r, dir, nil)
	if err := c.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	rules = "30001: from all fwmark 0x3001 lookup 3999\n30002: from all fwmark 0x3002 lookup 3002\n"
	if err := c.Health(context.Background(), cfg); err == nil {
		t.Fatalf("wrong lookup Health=%v", err)
	}
	actions, err := c.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("drift Plan=%#v err=%v", actions, err)
	}
}

func TestHealthValidatesSuppressedRouteState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "multiwan-suppressed.json")
	if err := os.WriteFile(state, []byte("{\"primary\":\"default via 192.0.2.1 dev wan0 metric 100\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "failover"
	cfg.Interfaces = []config.Interface{{ID: "if0", Name: "wan0"}}
	cfg.WANs = []config.WAN{{ID: "primary", Index: 1, Name: "Primary", Interface: "if0", Enabled: true}}
	live := ""
	r := &responseRunner{respond: func(command string) (string, error) {
		if strings.Contains(command, "route show default dev wan0") {
			return live, nil
		}
		return "", nil
	}}
	c := New(r, dir, nil)
	if err := c.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	live = "default via 192.0.2.1 dev wan0 metric 100\n"
	if err := c.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "одновременно") {
		t.Fatalf("live and suppressed route Health=%v", err)
	}
	live = ""
	cfg.MultiWAN.Enabled = false
	if err := c.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "вне режима") {
		t.Fatalf("disabled suppressed state Health=%v", err)
	}
}

func TestTickPreservesMemoryWhenPersistentStateIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "multiwan-suppressed.json")
	if err := os.WriteFile(state, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := &captureLogger{}
	c := New(&responseRunner{}, dir, logger)
	c.suppressed = nil
	c.tick(context.Background(), balanceConfig())
	if c.suppressed != nil {
		t.Fatalf("corrupt state replaced in-memory ownership: %#v", c.suppressed)
	}
	if len(logger.messages) == 0 {
		t.Fatal("corrupt state was not logged")
	}
}

func TestBalanceFailureRestoresEveryTouchedTableRuleAndOwnership(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "multiwan-balance.json")
	if err := os.WriteFile(owned, []byte("[1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRoutes := "default via 192.0.2.1 dev wan0 metric 100\nblackhole default metric 32767\n"
	r := &balanceStateRunner{
		routes: map[string]string{"3001": oldRoutes, "3002": ""},
		main: map[string]string{
			"wan0": "default via 192.0.2.1 dev wan0 metric 100\n",
			"wan1": "default via 198.51.100.1 dev wan1 metric 200\n",
		},
		rules:    map[string]string{"30001": "30001: from all fwmark 0x3001 lookup 3001"},
		failOnce: "route replace blackhole default metric 32767 table 3002",
	}
	c := New(r, dir, nil)
	if err := c.reconcileBalance(context.Background(), balanceConfig()); err == nil {
		t.Fatal("injected balance failure was ignored")
	}
	if r.routes["3001"] != oldRoutes || r.routes["3002"] != "" {
		t.Fatalf("tables not rolled back: %#v", r.routes)
	}
	if len(r.rules) != 1 || r.rules["30001"] != "30001: from all fwmark 0x3001 lookup 3001" {
		t.Fatalf("rules not rolled back: %#v", r.rules)
	}
	data, err := os.ReadFile(owned)
	if err != nil || string(data) != "[1]\n" {
		t.Fatalf("ownership not rolled back: %q err=%v", data, err)
	}
}

func TestTickRetriesFailedBalanceReconcileWithoutAnotherStateTransition(t *testing.T) {
	dir := t.TempDir()
	cfg := balanceConfig()
	for i := range cfg.WANs {
		cfg.WANs[i].Probe = config.Probe{Enabled: true, Type: "icmp", Targets: []string{"192.0.2.1"}, FailThreshold: 1}
	}
	r := &balanceStateRunner{
		routes: map[string]string{"3001": "", "3002": ""},
		main: map[string]string{
			"wan0": "default via 192.0.2.1 dev wan0 metric 100\n",
			"wan1": "default via 198.51.100.1 dev wan1 metric 200\n",
		},
		rules:    map[string]string{},
		failOnce: "route replace blackhole default metric 32767 table 3001",
	}
	logger := &captureLogger{}
	c := New(r, dir, logger)
	c.Probe = func(context.Context, config.WAN, string) bool { return false }
	c.tick(context.Background(), cfg)
	if !c.balanceDirty {
		t.Fatal("failed balance reconcile was forgotten")
	}
	if len(logger.messages) == 0 {
		t.Fatal("failed balance reconcile was not logged")
	}
	c.tick(context.Background(), cfg)
	if c.balanceDirty {
		t.Fatal("successful retry did not clear dirty state")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "multiwan-balance.json")); err != nil || string(data) != "[1,2]\n" {
		t.Fatalf("retry did not persist balance ownership: %q err=%v", data, err)
	}
}
