package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReport1953CommandErrorIncludesStderr(t *testing.T) {
	if os.Getenv("NETOS_TEST_STDERR_CHILD") == "1" {
		fmt.Fprintln(os.Stderr, `Cannot find device "br1"`)
		os.Exit(1)
	}
	m, _ := testManager()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	err = m.runOS(context.Background(), command{name: executable, args: []string{"-test.run=^TestReport1953CommandErrorIncludesStderr$"}, env: []string{"NETOS_TEST_STDERR_CHILD=1"}})
	if err == nil || !strings.Contains(err.Error(), "Cannot find device") {
		t.Fatalf("lost stderr: %v", err)
	}
}

func TestReport1953CleanupMissingDeviceAndRealFailure(t *testing.T) {
	for _, qos := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("qos=%v/missing=%v", qos, missing), func(t *testing.T) {
				m, _ := testManager()
				sandbox(t, m)
				filename, data := "owned-network-addresses.json", `[{"interface":"br1","address":"10.60.2.1/24"}]`
				if qos {
					filename, data = "owned-qos-clients.json", `["br1"]`
				}
				filename = filepath.Join(m.StateDir, "generated", filename)
				if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				restarted := false
				m.Run = func(ctx context.Context, c command) error {
					cmd := c.name + " " + strings.Join(c.args, " ")
					if cmd == "systemctl start netosd" {
						restarted = true
					}
					if strings.HasPrefix(cmd, "ip -4 addr del") || strings.HasPrefix(cmd, "tc qdisc del") {
						if missing {
							executable, err := os.Executable()
							if err != nil {
								return err
							}
							return m.runOS(ctx, command{name: executable, args: []string{"-test.run=^TestReport1953CommandErrorIncludesStderr$"}, env: []string{"NETOS_TEST_STDERR_CHILD=1"}})
						}
						return fmt.Errorf("Operation not permitted")
					}
					return nil
				}
				err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"})
				if missing && err != nil {
					t.Fatalf("missing device aborts reset: %v", err)
				}
				if !missing {
					if err == nil || !restarted {
						t.Fatalf("real failure must preserve error and restart daemon: %v, restarted=%v", err, restarted)
					}
					if _, err := os.Stat(filename); err != nil {
						t.Fatalf("lost ownership: %v", err)
					}
				}
			})
		}
	}
}
