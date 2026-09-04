package manage

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecuteDispatchesEveryReadOnlyAndServiceCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"status"}, "systemctl status --no-pager netosd"},
		{[]string{"logs"}, "journalctl -u netosd --no-pager -n 100"},
		{[]string{"logs", "--follow"}, "journalctl -u netosd --no-pager -n 100 -f"},
		{[]string{"start"}, "systemctl start netosd"},
		{[]string{"stop"}, "systemctl stop netosd"},
		{[]string{"restart"}, "systemctl restart netosd"},
		{[]string{"plan"}, "BIN -plan"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			m, _ := testManager()
			m.Binary = "BIN"
			var calls []string
			m.Run = func(_ context.Context, cmd command) error {
				calls = append(calls, cmd.name+" "+strings.Join(cmd.args, " "))
				return nil
			}
			if err := m.Execute(context.Background(), tc.args); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 1 || calls[0] != tc.want {
				t.Fatalf("calls=%v want=%q", calls, tc.want)
			}
		})
	}

	for _, artifact := range renderableArtifacts {
		t.Run("render_"+artifact, func(t *testing.T) {
			m, _ := testManager()
			m.Binary = "BIN"
			var got command
			m.Run = func(_ context.Context, cmd command) error { got = cmd; return nil }
			if err := m.Execute(context.Background(), []string{"render", artifact}); err != nil {
				t.Fatal(err)
			}
			if got.name != "BIN" || strings.Join(got.args, " ") != "-render "+artifact {
				t.Fatalf("command=%+v", got)
			}
		})
	}
}

func TestExecuteRejectsEveryInvalidCommandShape(t *testing.T) {
	cases := [][]string{
		{"version", "extra"}, {"status", "extra"}, {"logs", "--bad"},
		{"start", "extra"}, {"stop", "extra"}, {"restart", "extra"},
		{"plan", "extra"}, {"render"}, {"render", "not-real"}, {"backup", "extra"},
		{"update", "v1", "v2"}, {"update", "$(bad)"},
		{"reset", "--bad"}, {"reset", "--backup", "--no-backup"},
		{"restore", "one", "two"}, {"restore", "--unknown"},
		{"completion", "zsh"}, {"completion", "bash", "extra"},
		{"uninstall", "--bad"}, {"does-not-exist"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			m, _ := testManager()
			m.Run = func(context.Context, command) error {
				t.Fatal("invalid command executed an external process")
				return nil
			}
			if err := m.Execute(context.Background(), args); err == nil {
				t.Fatalf("invalid args accepted: %v", args)
			}
		})
	}
}

func TestHelpVersionAndCompletionAliases(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		m, out := testManager()
		if err := m.Execute(context.Background(), args); err != nil || !strings.Contains(out.String(), "netos status") {
			t.Fatalf("args=%v output=%q err=%v", args, out.String(), err)
		}
	}
	for _, alias := range []string{"version", "--version", "-v"} {
		m, out := testManager()
		if err := m.Execute(context.Background(), []string{alias}); err != nil || out.String() != "netOS v1.2.3\n" {
			t.Fatalf("alias=%s output=%q err=%v", alias, out.String(), err)
		}
	}
	for _, args := range [][]string{{"completion"}, {"completion", "bash"}} {
		m, out := testManager()
		if err := m.Execute(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		for _, artifact := range renderableArtifacts {
			if !strings.Contains(out.String(), artifact) {
				t.Fatalf("completion lacks %q", artifact)
			}
		}
	}
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"render", "--list"}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Fields(out.String()), renderableArtifacts; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("render --list=%v want=%v", got, want)
	}
}

func TestBackupNowCreatesRealEmptyArchiveAndRestartsDaemon(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	m.Now = func() time.Time { return time.Date(2026, 9, 1, 12, 34, 56, 0, time.UTC) }
	var calls []string
	m.Run = func(_ context.Context, cmd command) error {
		calls = append(calls, cmd.name+" "+strings.Join(cmd.args, " "))
		if cmd.name == "systemctl" && len(cmd.args) > 0 && cmd.args[0] == "start" {
			if err := os.MkdirAll(filepath.Dir(m.sys(m.ReadyFile)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(m.ReadyFile), []byte("ready\n"), 0o644)
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"backup"}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(m.BackupDir, "netos-backup-20260901-123456.tar.gz")
	if err := validateBackupArchive(archive); err != nil {
		t.Fatalf("empty backup is not a valid archive: %v", err)
	}
	if err := m.Execute(context.Background(), []string{"backup"}); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(m.BackupDir, "netos-backup-20260901-123456-2.tar.gz")
	if err := validateBackupArchive(second); err != nil {
		t.Fatalf("same-second backup is not a distinct valid archive: %v", err)
	}
	if !strings.Contains(out.String(), archive) || !strings.Contains(out.String(), second) || strings.Join(calls, "\n") != "systemctl stop netosd\nsystemctl start netosd\nsystemctl stop netosd\nsystemctl start netosd" {
		t.Fatalf("output=%q calls=%v", out.String(), calls)
	}
}

func TestBackupNowWaitsForFreshDaemonReadiness(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	ready := m.sys(m.ReadyFile)
	if err := os.MkdirAll(filepath.Dir(ready), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := false
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name == "systemctl" && len(cmd.args) > 0 && cmd.args[0] == "start" {
			started = true
			if _, err := os.Stat(ready); !os.IsNotExist(err) {
				return fmt.Errorf("stale readiness marker survived: %v", err)
			}
		}
		return nil
	}
	m.Output = func(context.Context, string, ...string) (string, error) { return "active\n", nil }
	sleeps := 0
	m.Sleep = func(time.Duration) {
		sleeps++
		if sleeps == 3 {
			if err := os.WriteFile(ready, []byte("fresh\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := m.Execute(context.Background(), []string{"backup"}); err != nil {
		t.Fatal(err)
	}
	if !started || sleeps != 3 || !strings.Contains(out.String(), "Резервная копия создана:") {
		t.Fatalf("started=%v sleeps=%d output=%q", started, sleeps, out.String())
	}
}

func TestBackupIncludesExistingDataAndUsesPrivateMode(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateDir, "netos.db"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tarArgs []string
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name != "tar" {
			return nil
		}
		tarArgs = append([]string(nil), cmd.args...)
		for i, arg := range cmd.args {
			if arg == "-czf" && i+1 < len(cmd.args) {
				return os.WriteFile(cmd.args[i+1], []byte("archive"), 0o666)
			}
		}
		return errors.New("archive path missing")
	}
	archive, err := m.backup(context.Background(), "manual")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(tarArgs) < 5 || tarArgs[0] != "-C" || tarArgs[2] != "-czf" {
		t.Fatalf("tar args=%v", tarArgs)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode=%04o", info.Mode().Perm())
	}
}

func TestHumanSizeAllUnits(t *testing.T) {
	for value, unit := range map[int64]string{1: "Б", 1024: "КБ", 1 << 20: "МБ"} {
		if got := humanSize(value); !strings.Contains(got, unit) {
			t.Fatalf("humanSize(%d)=%q", value, got)
		}
	}
}

func TestRestoreFailureAutomaticallyRestoresSafetyBackup(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(m.BackupDir, "netos-backup-target.tar.gz")
	valid, err := os.ReadFile(writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(m.StateDir, "netos.db")
	if err := os.WriteFile(dbPath, []byte("old-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	var safety string
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name == "tar" && contains(cmd.args, "-czf") {
			for i, arg := range cmd.args {
				if arg == "-czf" && i+1 < len(cmd.args) {
					safety = cmd.args[i+1]
					return os.WriteFile(safety, []byte("safety"), 0o600)
				}
			}
		}
		if cmd.name == "tar" && contains(cmd.args, "-xzf") {
			archive := cmd.args[len(cmd.args)-1]
			if archive == target {
				return errors.New("target extraction failed")
			}
			if archive == safety {
				if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
					return err
				}
				return os.WriteFile(dbPath, []byte("old-state"), 0o600)
			}
		}
		if cmd.name == "systemctl" && contains(cmd.args, "start") {
			if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0o644)
		}
		return nil
	}
	err = m.Execute(context.Background(), []string{"restore", target, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "автоматически восстановлено") {
		t.Fatalf("restore error=%v", err)
	}
	data, readErr := os.ReadFile(dbPath)
	if readErr != nil || string(data) != "old-state" {
		t.Fatalf("previous database was not restored: data=%q err=%v", data, readErr)
	}
}

func TestRestoreRollbackIgnoresCancelledCallerContext(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	safety := filepath.Join(m.BackupDir, "safety.tar.gz")
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(safety, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(m.StateDir, "netos.db")
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name == "tar" && contains(cmd.args, "-xzf") {
			if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
				return err
			}
			return os.WriteFile(dbPath, []byte("old-state"), 0o600)
		}
		return nil
	}
	m.Output = func(context.Context, string, ...string) (string, error) { return "active\n", nil }
	m.Sleep = func(time.Duration) {
		if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	callerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.rollbackRestore(callerCtx, safety, errors.New("target restore failed"))
	if err == nil || !strings.Contains(err.Error(), "автоматически восстановлено") {
		t.Fatalf("rollback error=%v", err)
	}
	if data, readErr := os.ReadFile(dbPath); readErr != nil || string(data) != "old-state" {
		t.Fatalf("rollback did not restore data: %q, %v", data, readErr)
	}
}

func TestBackupNowRestartsDaemonAfterArchiveFailure(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateDir, "netos.db"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	var started bool
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name == "tar" {
			return errors.New("tar failed")
		}
		if cmd.name == "systemctl" && len(cmd.args) > 0 && cmd.args[0] == "start" {
			started = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"backup"}); err == nil || !strings.Contains(err.Error(), "tar failed") {
		t.Fatalf("error=%v", err)
	}
	if !started {
		t.Fatal("daemon was not restarted after backup failure")
	}
}
