package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetAndRestoreRollbackRemoveOwnedMultiWAN(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		m, _ := testManager()
		sandbox(t, m)
		// Match the production multiwan.New(runner, stateDir, ...) layout;
		// Manager.StateDir is its parent, not the generated-state directory.
		generated := filepath.Join(m.StateDir, "generated")
		if err := os.MkdirAll(generated, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(generated, "multiwan-balance.json"), []byte(`[3]`), 0600); err != nil {
			t.Fatal(err)
		}
		previous := m.Output
		m.Output = func(ctx context.Context, name string, args ...string) (string, error) {
			if name == "ip" && strings.Join(args, " ") == "-4 rule show" {
				return "30003: from 192.0.2.5 lookup 3003\n30003: from all oif eth0 [detached] lookup 3003\n30004: from all lookup 3004\n30003: from all lookup 999\n", nil
			}
			return previous(ctx, name, args...)
		}
		var calls []string
		m.Run = func(_ context.Context, cmd command) error {
			calls = append(calls, cmd.name+" "+strings.Join(cmd.args, " "))
			return nil
		}
		if rollback {
			_ = m.rollbackRestore(context.Background(), "safety", errors.New("failed"), managementUplink{})
		} else {
			_ = m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"})
		}
		text := strings.Join(calls, "\n")
		for _, want := range []string{"ip -4 rule del priority 30003 from 192.0.2.5 lookup 3003", "ip -4 rule del priority 30003 from all oif eth0 lookup 3003", "ip -4 route flush table 3003"} {
			if !strings.Contains(text, want) {
				t.Errorf("rollback=%v missing %s", rollback, want)
			}
		}
		if strings.Contains(text, "del priority 30004") || strings.Contains(text, "del priority 30003 from all lookup 999") {
			t.Fatal("foreign rules removed")
		}
		if strings.Contains(text, "[detached]") {
			t.Fatal("iproute2 output annotation passed to ip rule del")
		}
	}
}

func TestMultiWANCleanupRetriesWithFreshRulesInOwnershipOrder(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	dir := filepath.Join(m.StateDir, "generated")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "multiwan-balance.json"), []byte("[2,1,2]"), 0600); err != nil {
		t.Fatal(err)
	}
	one := "30001: from all lookup 3001"
	two := "30002: from all lookup 3002"
	rules := strings.Join([]string{one, two, two, "30002: from all lookup 03002"}, "\n")
	m.Output = func(context.Context, string, ...string) (string, error) { return rules, nil }
	var calls []string
	failure := errors.New("second delete failed")
	m.Run = func(_ context.Context, cmd command) error {
		calls = append(calls, strings.Join(cmd.args, " "))
		if len(calls) == 2 && failure != nil {
			return failure
		}
		return nil
	}
	del := "-4 rule del priority 30002 from all lookup 3002"
	if err := m.removeOwnedMultiWAN(context.Background()); err != failure || strings.Join(calls, "\n") != del+"\n"+del {
		t.Fatalf("first attempt: %v, %v", calls, err)
	}
	failure = nil
	rules = one + "\n" + two
	calls = nil
	want := strings.Join([]string{del, "-4 route flush table 3002", "-4 rule del priority 30001 from all lookup 3001", "-4 route flush table 3001"}, "\n")
	if err := m.removeOwnedMultiWAN(context.Background()); err != nil || strings.Join(calls, "\n") != want {
		t.Fatalf("retry: %v, %v", calls, err)
	}
}
