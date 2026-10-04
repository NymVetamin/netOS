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
