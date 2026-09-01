package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeSet struct {
	family  string
	timeout int
	entries []string
}

type policyRunner struct {
	sets         map[string]fakeSet
	inUse        map[string]bool
	commands     []string
	failContains string
}

func newPolicyRunner() *policyRunner {
	return &policyRunner{sets: map[string]fakeSet{}, inUse: map[string]bool{}}
}

func (r *policyRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failContains != "" && strings.Contains(command, r.failContains) {
		return "", fmt.Errorf("injected %s", r.failContains)
	}
	if name != "ipset" || len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "list":
		if len(args) == 2 && args[1] == "-name" {
			names := make([]string, 0, len(r.sets))
			for set := range r.sets {
				names = append(names, set)
			}
			sort.Strings(names)
			return strings.Join(names, "\n") + "\n", nil
		}
		set, ok := r.sets[args[1]]
		if !ok {
			return "", fmt.Errorf("does not exist")
		}
		return fmt.Sprintf("Name: %s\nType: hash:ip\nHeader: family %s hashsize 1024 maxelem 65536 timeout %d\n", args[1], set.family, set.timeout), nil
	case "save":
		set, ok := r.sets[args[1]]
		if !ok {
			return "", fmt.Errorf("does not exist")
		}
		var out strings.Builder
		fmt.Fprintf(&out, "create %s hash:ip family %s timeout %d\n", args[1], set.family, set.timeout)
		for _, entry := range set.entries {
			fmt.Fprintf(&out, "add %s %s\n", args[1], entry)
		}
		return out.String(), nil
	case "create":
		timeout := 0
		_, _ = fmt.Sscan(args[6], &timeout)
		r.sets[args[1]] = fakeSet{family: args[4], timeout: timeout}
	case "destroy":
		if _, ok := r.sets[args[1]]; !ok {
			return "", fmt.Errorf("does not exist")
		}
		if r.inUse[args[1]] {
			return "", fmt.Errorf("set is in use")
		}
		delete(r.sets, args[1])
	}
	return "", nil
}

func (r *policyRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	if name == "ipset" && len(args) == 1 && args[0] == "restore" {
		r.commands = append(r.commands, "ipset restore")
		for _, line := range strings.Split(input, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "create":
				timeout := 0
				_, _ = fmt.Sscan(fields[6], &timeout)
				r.sets[fields[1]] = fakeSet{family: fields[4], timeout: timeout}
			case "add":
				set := r.sets[fields[1]]
				set.entries = append(set.entries, fields[2])
				r.sets[fields[1]] = set
			}
		}
		return "", nil
	}
	return r.Run(ctx, name, args...)
}

func domainPolicyConfig(id string) *config.Config {
	cfg := config.Default()
	cfg.Policies = []config.Policy{{ID: id, Name: "Domains", Enabled: true, Priority: 10, Channel: "direct", Domains: []string{"example.com"}}}
	return cfg
}

func TestPolicyIPSetLifecyclePreservesLearnedEntries(t *testing.T) {
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	cleanup := NewCleanup(r, s.StateDir)
	cfg := domainPolicyConfig("domains")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 1 || r.sets[IPv4SetName("domains")].family != "inet" {
		t.Fatalf("sets=%+v", r.sets)
	}
	set := r.sets[IPv4SetName("domains")]
	set.entries = []string{"192.0.2.1"}
	r.sets[IPv4SetName("domains")] = set
	r.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.sets[IPv4SetName("domains")].entries) != 1 {
		t.Fatal("idempotent Apply flushed learned entries")
	}
	for _, command := range r.commands {
		if strings.Contains(command, " create ") || strings.Contains(command, " destroy ") {
			t.Fatalf("clean Apply mutated sets: %v", r.commands)
		}
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) != 0 {
		t.Fatalf("clean plan=%#v err=%v", actions, err)
	}

	off := config.Default()
	if err := s.Apply(context.Background(), off); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 1 {
		t.Fatalf("prepare removed sets before firewall: %+v", r.sets)
	}
	if err := cleanup.Apply(context.Background(), off); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 0 {
		t.Fatalf("stale sets=%+v", r.sets)
	}
	if err := s.Health(context.Background(), off); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyDomainDefinitionChangeFlushesLearnedEntries(t *testing.T) {
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	cfg := domainPolicyConfig("domains")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	set := r.sets[IPv4SetName("domains")]
	set.entries = []string{"192.0.2.5"}
	r.sets[IPv4SetName("domains")] = set
	cfg.Policies[0].Domains = []string{"other.example"}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if entries := r.sets[IPv4SetName("domains")].entries; len(entries) != 0 {
		t.Fatalf("old learned entries survived domain edit: %v", entries)
	}
}

func TestPolicyIPSetRejectsForeignCollisionAndUnsafeOwnership(t *testing.T) {
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	cfg := domainPolicyConfig("domains")
	r.sets[IPv4SetName("domains")] = fakeSet{family: "inet", timeout: DomainSetTimeout}
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "не принадлежит") {
		t.Fatalf("collision error=%v", err)
	}
	if err := os.WriteFile(s.ownedPath(), []byte(`[{"policy":"x","name":"foreign","family":"inet","definition":"0123456789abcdef"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "небезопасный") {
		t.Fatalf("unsafe ownership error=%v", err)
	}
}

func TestPolicyIPSetFailureRollsBackKernelAndOwnership(t *testing.T) {
	r := newPolicyRunner()
	dir := t.TempDir()
	s := New(r, dir)
	oldCfg := domainPolicyConfig("old")
	if err := s.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	oldSet := r.sets[IPv4SetName("old")]
	oldSet.entries = []string{"198.51.100.7"}
	r.sets[IPv4SetName("old")] = oldSet
	r.inUse[IPv4SetName("old")] = true
	stateBefore, err := os.ReadFile(filepath.Join(dir, "owned-policy-ipsets.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.failContains = "create " + IPv4SetName("new")
	if err := s.Apply(context.Background(), domainPolicyConfig("new")); err == nil {
		t.Fatal("injected create failure accepted")
	}
	if _, ok := r.sets[IPv4SetName("new")]; ok {
		t.Fatal("partially created set survived rollback")
	}
	if got := r.sets[IPv4SetName("old")].entries; len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("old entries=%v", got)
	}
	stateAfter, _ := os.ReadFile(filepath.Join(dir, "owned-policy-ipsets.json"))
	if string(stateAfter) != string(stateBefore) {
		t.Fatalf("ownership changed before=%q after=%q", stateBefore, stateAfter)
	}
}

func TestXrayInboundDomainPolicyDoesNotCreateKernelSets(t *testing.T) {
	cfg := domainPolicyConfig("xray-domain")
	cfg.VPNServers = []config.VPNServer{{ID: "xray", Type: "xray"}}
	cfg.Policies[0].VPNServer = "xray"
	if sets := desiredSets(cfg); len(sets) != 0 {
		t.Fatalf("Xray-native policy sets=%+v", sets)
	}
}

func TestOwnedSetNamesRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	s := New(newPolicyRunner(), dir)
	if err := s.Apply(context.Background(), domainPolicyConfig("safe")); err != nil {
		t.Fatal(err)
	}
	names, err := OwnedSetNames(dir)
	if err != nil || len(names) != 1 {
		t.Fatalf("names=%v err=%v", names, err)
	}
	if err := os.WriteFile(s.ownedPath(), []byte(`[{"policy":"safe","name":"foreign","family":"inet","definition":"0123456789abcdef"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OwnedSetNames(dir); err == nil {
		t.Fatal("tampered ownership accepted")
	}
}

func TestEmptyPolicyConfigDoesNotRequireIPSet(t *testing.T) {
	r := newPolicyRunner()
	s := New(r, t.TempDir())
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != 0 {
		t.Fatalf("empty config invoked system tools: %v", r.commands)
	}
}

func TestPrepareAndCleanupStraddleFirewallSwitch(t *testing.T) {
	r := newPolicyRunner()
	dir := t.TempDir()
	prepare, cleanup := New(r, dir), NewCleanup(r, dir)
	oldCfg, newCfg := domainPolicyConfig("old"), domainPolicyConfig("new")
	if err := prepare.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	r.inUse[IPv4SetName("old")] = true
	if err := prepare.Apply(context.Background(), newCfg); err != nil {
		t.Fatalf("prepare touched firewall-referenced old set: %v", err)
	}
	if len(r.sets) != 2 {
		t.Fatalf("sets before firewall switch=%+v", r.sets)
	}
	r.inUse = map[string]bool{IPv4SetName("new"): true}
	if err := cleanup.Apply(context.Background(), newCfg); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 1 {
		t.Fatalf("stale sets survived post-firewall cleanup: %+v", r.sets)
	}
}

func TestCleanupFailureRestoresOnlySetsAlreadyDestroyed(t *testing.T) {
	r := newPolicyRunner()
	dir := t.TempDir()
	prepare, cleanup := New(r, dir), NewCleanup(r, dir)
	cfg := domainPolicyConfig("one")
	cfg.Policies = append(cfg.Policies, config.Policy{ID: "two", Name: "Two", Enabled: true, Priority: 20, Channel: "direct", Domains: []string{"two.example"}})
	if err := prepare.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	names := []string{IPv4SetName("one"), IPv4SetName("two")}
	sort.Strings(names)
	first := r.sets[names[0]]
	first.entries = []string{"192.0.2.9"}
	r.sets[names[0]] = first
	stateBefore, err := os.ReadFile(filepath.Join(dir, "owned-policy-ipsets.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.failContains = "destroy " + names[1]
	if err := cleanup.Apply(context.Background(), config.Default()); err == nil {
		t.Fatal("injected cleanup failure accepted")
	}
	if len(r.sets) != 2 || len(r.sets[names[0]].entries) != 1 {
		t.Fatalf("cleanup rollback sets=%+v", r.sets)
	}
	stateAfter, _ := os.ReadFile(filepath.Join(dir, "owned-policy-ipsets.json"))
	if string(stateAfter) != string(stateBefore) {
		t.Fatalf("ownership changed before=%q after=%q", stateBefore, stateAfter)
	}
}
