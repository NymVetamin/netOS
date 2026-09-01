package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type firewallCall struct {
	name  string
	args  []string
	input string
}

type firewallRunner struct {
	outputs     map[string]string
	runErrors   map[string]error
	inputErrors map[string][]error
	calls       []firewallCall
}

func (r *firewallRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, firewallCall{name: name, args: append([]string(nil), args...)})
	return r.outputs[name], r.runErrors[name]
}

func (r *firewallRunner) RunInput(_ context.Context, input, name string, args ...string) (string, error) {
	r.calls = append(r.calls, firewallCall{name: name, args: append([]string(nil), args...), input: input})
	key := name + " " + strings.Join(args, " ")
	queue := r.inputErrors[key]
	if len(queue) == 0 {
		return "", nil
	}
	err := queue[0]
	r.inputErrors[key] = queue[1:]
	return "", err
}

func configuredFirewall(t *testing.T) (*config.Config, *Ruleset) {
	t.Helper()
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "lan0", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan-if", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, rules
}

func cleanFirewallRunner(rules *Ruleset) *firewallRunner {
	return &firewallRunner{
		outputs:   map[string]string{"iptables-save": rules.IPv4, "ip6tables-save": rules.IPv6},
		runErrors: map[string]error{}, inputErrors: map[string][]error{},
	}
}

func TestSubsystemIdentityAndCommandVariants(t *testing.T) {
	s := New(&firewallRunner{}, t.TempDir())
	if s.Name() != "firewall" || s.restoreCmd() != "iptables-restore" || s.restore6Cmd() != "ip6tables-restore" {
		t.Fatalf("unexpected subsystem: %+v", s)
	}
	s.Legacy = true
	if s.restoreCmd() != "iptables-legacy-restore" || s.restore6Cmd() != "ip6tables-legacy-restore" {
		t.Fatal("legacy commands were not selected")
	}
}

func TestPlanInitialConfigDiffCleanAndLiveDrift(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	s := New(cleanFirewallRunner(rules), t.TempDir())
	actions, err := s.Plan(nil, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "create" || actions[0].Target != "iptables" || !strings.Contains(actions[0].Detail, "правил") {
		t.Fatalf("initial plan: actions=%+v err=%v", actions, err)
	}
	if actions, err = s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
		t.Fatalf("clean plan: actions=%+v err=%v", actions, err)
	}

	changedValue := *cfg
	changed := &changedValue
	changed.Firewall.OutputPolicy = "drop"
	actions, err = s.Plan(cfg, changed)
	if err != nil || len(actions) == 0 || actions[0].Target != "iptables" || !strings.Contains(actions[0].Detail, "+") {
		t.Fatalf("config diff plan: actions=%+v err=%v", actions, err)
	}

	driftRunner := cleanFirewallRunner(rules)
	driftRunner.outputs["iptables-save"] = strings.Replace(rules.IPv4, "-A INPUT", "-A INPUT -s 198.51.100.1", 1)
	s.Runner = driftRunner
	actions, err = s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Target != "iptables" || !strings.Contains(actions[0].Detail, "расхождения") {
		t.Fatalf("live drift plan: actions=%+v err=%v", actions, err)
	}
}

func TestPlanReportsIPv6ConfigAndLiveDrift(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	changedValue := *cfg
	changed := &changedValue
	changed.IPv6.Mode = "native"
	s := New(cleanFirewallRunner(rules), t.TempDir())
	actions, err := s.Plan(cfg, changed)
	if err != nil || len(actions) == 0 {
		t.Fatalf("IPv6 config plan: actions=%+v err=%v", actions, err)
	}
	found := false
	for _, action := range actions {
		if action.Target == "ip6tables" {
			found = true
		}
	}
	if !found {
		t.Fatalf("IPv6 action absent: %+v", actions)
	}

	runner := cleanFirewallRunner(rules)
	runner.outputs["ip6tables-save"] = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
	s.Runner = runner
	actions, err = s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Target != "ip6tables" {
		t.Fatalf("IPv6 drift plan: actions=%+v err=%v", actions, err)
	}
}

func TestPlanPropagatesBuildAndLiveReadErrors(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	runner := cleanFirewallRunner(rules)
	runner.outputs["iptables-save"] = ""
	runner.outputs["ip6tables-save"] = ""
	runner.runErrors["iptables-save"] = errors.New("save failed")
	s := New(runner, t.TempDir())
	if _, err := s.Plan(cfg, cfg); err == nil || !strings.Contains(err.Error(), "save failed") {
		t.Fatalf("live read error ignored: %v", err)
	}
}

func TestApplyPreflightsPersistsAndAppliesBothFamilies(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	runner := cleanFirewallRunner(rules)
	runner.outputs["iptables-save"] = ""
	runner.outputs["ip6tables-save"] = ""
	dir := t.TempDir()
	s := New(runner, dir)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("calls=%+v", runner.calls)
	}
	want := []struct {
		name string
		test bool
	}{
		{"iptables-restore", true}, {"ip6tables-restore", true}, {"ip6tables-restore", false}, {"iptables-restore", false},
	}
	for i, expected := range want {
		got := runner.calls[i+2]
		if got.name != expected.name || (len(got.args) == 1) != expected.test || (expected.test && got.args[0] != "--test") {
			t.Fatalf("call[%d]=%+v want=%+v", i, got, expected)
		}
	}
	for name, content := range map[string]string{"iptables.rules": rules.IPv4, "ip6tables.rules": rules.IPv6} {
		path := filepath.Join(dir, name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("%s got=%q err=%v", name, got, err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode=%v err=%v", name, info.Mode(), err)
			}
		}
	}
	boot, err := s.RestoreOnBoot()
	if err != nil || string(boot) != rules.IPv4 {
		t.Fatalf("boot=%q err=%v", boot, err)
	}
}

func TestApplyPreflightFailureDoesNotTouchPersistedState(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	runner := cleanFirewallRunner(rules)
	runner.outputs["iptables-save"] = ""
	runner.outputs["ip6tables-save"] = ""
	runner.inputErrors["iptables-restore --test"] = []error{errors.New("syntax rejected")}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iptables.rules"), []byte("old4"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(runner, dir)
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "проверка") {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "iptables.rules"))
	if string(got) != "old4" || len(runner.calls) != 3 {
		t.Fatalf("state=%q calls=%+v", got, runner.calls)
	}
}

func TestApplyIsNoOpWhenRuntimeAndProtectedFilesMatch(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	dir := t.TempDir()
	for name, content := range map[string]string{"iptables.rules": rules.IPv4, "ip6tables.rules": rules.IPv6} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(filepath.Join(dir, "iptables.rules"))
	if err != nil {
		t.Fatal(err)
	}
	runner := cleanFirewallRunner(rules)
	s := New(runner, dir)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(dir, "iptables.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].name != "iptables-save" || runner.calls[1].name != "ip6tables-save" {
		t.Fatalf("idempotent Apply mutated firewall: %+v", runner.calls)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("state file rewritten: %v -> %v", before.ModTime(), after.ModTime())
	}
}

func TestApplyRepairsOnlyPersistedStateWhenRuntimeMatches(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iptables.rules"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := cleanFirewallRunner(rules)
	s := New(runner, dir)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("state-only repair touched runtime: %+v", runner.calls)
	}
	got4, _ := os.ReadFile(filepath.Join(dir, "iptables.rules"))
	got6, _ := os.ReadFile(filepath.Join(dir, "ip6tables.rules"))
	if string(got4) != rules.IPv4 || string(got6) != rules.IPv6 {
		t.Fatalf("state repair=%q/%q", got4, got6)
	}
}

func TestApplyAcceptsMissingIPv6KernelButNotOtherIPv6Errors(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	missing := cleanFirewallRunner(rules)
	missing.outputs["iptables-save"] = ""
	missing.outputs["ip6tables-save"] = ""
	missing.inputErrors["ip6tables-restore --test"] = []error{errors.New("Table does not exist")}
	missing.inputErrors["ip6tables-restore "] = []error{errors.New("NO SUCH FILE")}
	if err := New(missing, t.TempDir()).Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	rejected := cleanFirewallRunner(rules)
	rejected.outputs["iptables-save"] = ""
	rejected.outputs["ip6tables-save"] = ""
	rejected.inputErrors["ip6tables-restore --test"] = []error{errors.New("invalid rule")}
	if err := New(rejected, t.TempDir()).Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "ip6tables") {
		t.Fatalf("IPv6 preflight error ignored: %v", err)
	}
}

func TestApplyFailureRestoresPreviousFilesAndRuntime(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	dir := t.TempDir()
	old4, old6 := "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	if err := os.WriteFile(filepath.Join(dir, "iptables.rules"), []byte(old4), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ip6tables.rules"), []byte(old6), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := cleanFirewallRunner(rules)
	live4 := "*filter\n:INPUT ACCEPT [12:34]\nCOMMIT\n"
	live6 := "*filter\n:INPUT DROP [56:78]\nCOMMIT\n"
	runner.outputs["iptables-save"] = live4
	runner.outputs["ip6tables-save"] = live6
	runner.inputErrors["iptables-restore "] = []error{errors.New("apply failed"), nil}
	s := New(runner, dir)
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("error=%v", err)
	}
	got4, _ := os.ReadFile(filepath.Join(dir, "iptables.rules"))
	got6, _ := os.ReadFile(filepath.Join(dir, "ip6tables.rules"))
	if string(got4) != old4 || string(got6) != old6 {
		t.Fatalf("files not restored: %q %q", got4, got6)
	}
	if len(runner.calls) != 8 || runner.calls[6].input != live6 || runner.calls[7].input != live4 {
		t.Fatalf("runtime rollback calls=%+v", runner.calls)
	}
}

func TestHealthComparesEveryManagedRuleAndBothFamilies(t *testing.T) {
	cfg, rules := configuredFirewall(t)
	runner := cleanFirewallRunner(rules)
	s := New(runner, t.TempDir())
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	// Kernel counters and unmanaged tables do not constitute configuration drift.
	runner.outputs["iptables-save"] = "*raw\n:PREROUTING ACCEPT [9:9]\nCOMMIT\n" + strings.ReplaceAll(rules.IPv4, "[0:0]", "[123:456]")
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("counter/unmanaged drift: %v", err)
	}

	runner.outputs["iptables-save"] = strings.Replace(rules.IPv4, "-A INPUT", "-A INPUT -s 198.51.100.2", 1)
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "iptables") {
		t.Fatalf("IPv4 rule drift accepted: %v", err)
	}
	runner.outputs["iptables-save"] = rules.IPv4
	runner.outputs["ip6tables-save"] = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "ip6tables") {
		t.Fatalf("IPv6 rule drift accepted: %v", err)
	}
}

func TestHealthChecksDisabledFirewallAndHandlesReadFailures(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.Enabled = false
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runner := cleanFirewallRunner(rules)
	s := New(runner, t.TempDir())
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	runner.outputs["iptables-save"] = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("disabled-firewall drift was accepted")
	}
	runner.outputs["iptables-save"] = rules.IPv4
	runner.runErrors["ip6tables-save"] = errors.New("not found")
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("missing IPv6 kernel: %v", err)
	}
	runner.runErrors["ip6tables-save"] = errors.New("permission denied")
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("read error ignored: %v", err)
	}
}

func TestRulesetAccountingNormalizationAndSnapshots(t *testing.T) {
	old := "*filter\n:A - [0:0]\n-A A -j ACCEPT\nCOMMIT\n"
	next := "*filter\n:A - [0:0]\n-A A -j DROP\nCOMMIT\n"
	if got := countRules(old); got != 1 {
		t.Fatalf("count=%d", got)
	}
	if added, removed := diffCount(old, next); added != 1 || removed != 1 {
		t.Fatalf("diff=%d/%d", added, removed)
	}
	live := "# generated\r\n*raw\r\n:X - [1:2]\r\nCOMMIT\r\n*filter\r\n:A - [7:8]\r\n-A A -j ACCEPT\r\nCOMMIT\r\n"
	if !rulesetMatches(live, old) {
		t.Fatalf("normalization mismatch: %q", normalizeRuleset(live))
	}
	if rulesetMatches(live, next) {
		t.Fatal("different rule matched")
	}

	path := filepath.Join(t.TempDir(), "rules")
	snapshot, err := snapshotRuleset(path)
	if err != nil || snapshot.exists {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if err := os.WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreRulesetSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("new file was not removed: %v", err)
	}
}

func TestRulesetMatchesCanonicalizesNFTSaveWithoutIgnoringRuleOrder(t *testing.T) {
	expected := `*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ZONE - [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -o eth0 -j ZONE
-A ZONE -p udp --dport 53 -j ACCEPT
-A ZONE -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
`
	live := `# Generated by iptables-save
*nat
:POSTROUTING ACCEPT [8:9]
:PREROUTING ACCEPT [1:2]
COMMIT
# Completed
*filter
:ZONE - [0:0]
:OUTPUT ACCEPT [3:4]
:INPUT DROP [5:6]
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth0 -j ZONE
-A ZONE -p udp -m udp --dport 53 -j ACCEPT
-A ZONE -j DROP
COMMIT
`
	if !rulesetMatches(live, expected) {
		t.Fatal("semantic nft-save canonicalization was treated as drift")
	}
	reordered := strings.Replace(live,
		"-A ZONE -p udp -m udp --dport 53 -j ACCEPT\n-A ZONE -j DROP",
		"-A ZONE -j DROP\n-A ZONE -p udp -m udp --dport 53 -j ACCEPT", 1)
	if rulesetMatches(reordered, expected) {
		t.Fatal("order change inside one chain was ignored")
	}
}
