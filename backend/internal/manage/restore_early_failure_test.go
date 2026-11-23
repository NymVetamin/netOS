package manage

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkRestoreEarlyStartFailure(t *testing.T, startFailure func(context.Context) error) {
	t.Helper()
	for _, stage := range []string{"backup", "uplink"} {
		t.Run(stage, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			seedBackupDatabase(t, m)
			target := writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
			dbPath := filepath.Join(m.StateDir, "netos.db")
			before, err := os.ReadFile(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(m.sys("/sys/class/net/eth0/device"), 0755); err != nil {
				t.Fatal(err)
			}
			m.Output = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "ip" && strings.Join(args, " ") == "-4 route show default" {
					return "default via 192.0.2.1 dev eth0", nil
				}
				if name == "ip" && strings.Join(args, " ") == "-o -4 addr show dev eth0" {
					return "2: eth0 inet 192.0.2.2/24", nil
				}
				return "", nil
			}
			primary := errors.New("fixture primary " + stage)
			for _, failStart := range []bool{true, false, true} {
				starts, extracts := 0, 0
				var startErr error
				m.Run = func(ctx context.Context, cmd command) error {
					if cmd.name == "tar" && contains(cmd.args, "-czf") {
						if stage == "backup" {
							return primary
						}
						for i, arg := range cmd.args {
							if arg == "-czf" {
								return writeMockBackup(t, cmd.args[i+1])
							}
						}
					}
					if cmd.name == "ip" && contains(cmd.args, "replace") && stage == "uplink" {
						return primary
					}
					if cmd.name == "tar" && contains(cmd.args, "-xzf") {
						extracts++
					}
					if cmd.name == "systemctl" && strings.Join(cmd.args, " ") == "start netosd" {
						starts++
						if failStart {
							startErr = startFailure(ctx)
							return startErr
						}
					}
					return nil
				}
				err := m.Execute(context.Background(), []string{"restore", target, "--yes"})
				if !errors.Is(err, primary) {
					t.Fatal("lost primary cause", err)
				}
				if failStart && (startErr == nil || !errors.Is(err, startErr) || !strings.Contains(err.Error(), "netosd")) {
					t.Fatal("lost restart failure", err, startErr)
				}
				if starts != 1 || extracts != 0 {
					t.Fatal("unexpected recovery commands", starts, extracts)
				}
				after, readErr := os.ReadFile(dbPath)
				if readErr != nil || string(after) != string(before) {
					t.Fatal("early failure changed original database", readErr)
				}
			}
		})
	}
}

func TestRestoreEarlyStartFailure(t *testing.T) {
	checkRestoreEarlyStartFailure(t, func(context.Context) error { return errors.New("fixture start refusal") })
}
