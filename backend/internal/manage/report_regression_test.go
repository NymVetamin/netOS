package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportResetAndRollbackCleanOwnedRuntime(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "rollback"}[rollback], func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			generated := filepath.Join(m.StateDir, "generated")
			if err := os.MkdirAll(generated, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{
				"owned-qos.json":               `[{"interface":"eth3","ifb":"ifb-netos-1"}]`,
				"owned-qos-clients.json":       `["eth6"]`,
				"owned-network-addresses.json": `[{"interface":"eth6","address":"10.60.1.1/24"}]`,
				"owned-wan-addresses.json":     `[{"interface":"eth4","address":"203.0.113.101/24"}]`,
			} {
				if err := os.WriteFile(filepath.Join(generated, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var commands []string
			m.Run = func(_ context.Context, c command) error {
				commands = append(commands, c.name+" "+strings.Join(c.args, " "))
				return nil
			}
			if rollback {
				_ = m.rollbackRestore(context.Background(), "safety", errors.New("startup failure"), managementUplink{})
			} else {
				if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err != nil {
					t.Fatal(err)
				}
			}
			out := strings.Join(commands, "\n")
			for _, want := range []string{"tc qdisc del dev eth3 ingress", "tc qdisc del dev eth6 root", "ip -4 addr del 10.60.1.1/24 dev eth6", "ip -4 addr del 203.0.113.101/24 dev eth4"} {
				if !strings.Contains(out, want) {
					t.Errorf("missing cleanup: %s", want)
				}
			}
		})
	}
}

func TestReportReinstallNetworkFailureIsNotMissingRelease(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("curl: (35) Connection reset by peer")
	}
	err := m.Execute(context.Background(), []string{"reinstall", "v0.06"})
	if err == nil || strings.Contains(err.Error(), "готового релиза v0.06 нет") || !strings.Contains(err.Error(), "Connection reset") {
		t.Fatalf("wrong cause: %v", err)
	}
}

func TestReportFailedQoSCleanupPreservesOwnership(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "rollback"}[rollback], func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			path := filepath.Join(m.StateDir, "generated", "owned-qos.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`[{"interface":"eth3","ifb":"ifb-netos-1"}]`), 0600); err != nil {
				t.Fatal(err)
			}
			m.Run = func(_ context.Context, c command) error {
				if c.name == "tc" {
					return errors.New("Operation not permitted")
				}
				return nil
			}
			var err error
			if rollback {
				err = m.rollbackRestore(context.Background(), "safety", errors.New("startup failure"), managementUplink{})
			} else {
				err = m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"})
			}
			if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
				t.Fatalf("cleanup failure hidden: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("lost ownership after failed cleanup: %v", err)
			}
		})
	}
}
