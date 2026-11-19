package manage

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
		{[]string{"logs", "--system"}, "journalctl -u netosd --no-pager -n 100"},
		{[]string{"logs", "--system", "--follow"}, "journalctl -u netosd --no-pager -n 100 -f"},
		{[]string{"start"}, "systemctl start netosd"},
		{[]string{"stop"}, "systemctl stop netosd"},
		{[]string{"restart"}, "systemctl restart netosd"},
		{[]string{"plan"}, "BIN -plan"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			m, _ := testManager()
			// Exercise the systemctl fallback without contacting a running daemon.
			m.Root = t.TempDir()
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

func TestCommandsRejectMissingBackupDatabase(t *testing.T) {
	for _, args := range [][]string{{"backup"}, {"reset", "--yes", "--backup"}, {"uninstall", "--yes", "--backup"}} {
		t.Run(args[0], func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			var starts int
			m.Run = func(_ context.Context, cmd command) error {
				if cmd.name == "tar" || cmd.name == "iptables-restore" {
					t.Fatalf("unexpected command %s", cmd.name)
				}
				if cmd.name == "systemctl" && cmd.args[0] == "start" {
					starts++
				}
				return nil
			}
			for i := 0; i < 2; i++ {
				if i == 1 {
					if err := os.MkdirAll(m.StateDir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(m.StateDir, "netos.db"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := m.Execute(context.Background(), args); err == nil || !strings.Contains(err.Error(), "netos.db") {
					t.Fatalf("expected database error, got %v", err)
				}
				if entries, err := m.listBackups(); err != nil || len(entries) != 0 || starts != i+1 {
					t.Fatalf("backups=%v, err=%v, restart count=%d", entries, err, starts)
				}
			}
			if strings.Contains(out.String(), "Резервная копия создана:") {
				t.Fatal(out.String())
			}
		})
	}
}

func TestBackupNowWaitsForFreshDaemonReadiness(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	seedBackupDatabase(t, m)
	ready := m.sys(m.ReadyFile)
	if err := os.MkdirAll(filepath.Dir(ready), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := false
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name == "tar" {
			return os.WriteFile(cmd.args[3], []byte("archive"), 0600)
		}
		if cmd.name == "systemctl" && len(cmd.args) > 0 && cmd.args[0] == "start" {
			started = true
			if _, err := os.Stat(ready); !os.IsNotExist(err) {
				return fmt.Errorf("stale readiness marker survived: %v", err)
			}
		}
		return nil
	}
	m.Output = func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "nft" {
			return "", nil
		}
		return "active\n", nil
	}
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

func TestBackupReportsArchiveAndRestartFailures(t *testing.T) {
	archiveErr, startErr := errors.New("archive failed"), errors.New("start failed")
	for _, tc := range []struct {
		name                     string
		archive, marker, restart bool
	}{
		{"archive", true, false, false}, {"restart", false, false, true},
		{"both", true, false, true}, {"marker and restart", false, true, true}, {"all", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			if err := os.MkdirAll(m.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.StateDir, "netos.db"), []byte("state"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.marker {
				ready := m.sys(m.ReadyFile)
				if err := os.MkdirAll(ready, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ready, "occupied"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			m.Run = func(_ context.Context, cmd command) error {
				if cmd.name == "tar" {
					if tc.archive {
						return archiveErr
					}
					return os.WriteFile(cmd.args[3], []byte("archive"), 0600)
				}
				if cmd.name == "systemctl" && cmd.args[0] == "start" {
					starts++
					if tc.restart {
						return startErr
					}
				}
				return nil
			}
			for attempt := 1; attempt <= 2; attempt++ {
				err := m.Execute(context.Background(), []string{"backup"})
				if err == nil || starts != attempt || errors.Is(err, archiveErr) != tc.archive || errors.Is(err, startErr) != tc.restart {
					t.Fatalf("attempt %d: starts=%d err=%v", attempt, starts, err)
				}
				message := err.Error()
				if strings.Contains(message, "маркер готовности") != tc.marker || strings.Contains(message, "создана в") == tc.archive ||
					tc.restart && strings.Contains(message, "служба запущена") || strings.Contains(out.String(), "Резервная копия создана:") {
					t.Fatalf("misleading result: %v, output=%q", err, out.String())
				}
			}
		})
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

// Statistics stores are left out of a copy; settings, including the database
// WAL that may hold committed changes after a crash, stay. Real GNU tar.
func TestBackupLeavesOutStatisticsWithRealTar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("GNU tar semantics are checked on Linux")
	}
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip(err)
	}
	m, _ := testManager()
	sandbox(t, m)
	m.Run = m.runOS
	files := map[string]bool{ // name -> expected in the copy
		"netos.db": true, "netos.db-wal": true, "netos.db-shm": true, "generated/dnsmasq.conf": true,
		"second-history.sqlite": false, "second-history.sqlite-wal": false, "second-history.sqlite-shm": false,
		"client-history.sqlite": false, "client-history.sqlite-wal": false, "client-history.sqlite-journal": false,
		"traffic-history.json": false,
	}
	for name := range files {
		path := filepath.Join(m.StateDir, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := m.backup(context.Background(), "manual")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	state := strings.TrimPrefix(filepath.Clean(m.StateDir), "/") + "/"
	for r := tar.NewReader(gz); ; {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[strings.TrimPrefix(h.Name, state)] = true
	}
	for name, want := range files {
		if got[name] != want {
			t.Fatalf("%s in copy = %v, want %v; copy: %v", name, got[name], want, got)
		}
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
	m.Output = func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "nft" {
			return "", nil
		}
		return "active\n", nil
	}
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
	err := m.rollbackRestore(callerCtx, safety, errors.New("target restore failed"), managementUplink{})
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
			for i, arg := range cmd.args {
				if arg == "-czf" && i+1 < len(cmd.args) {
					if err := os.WriteFile(cmd.args[i+1], []byte("truncated archive"), 0o600); err != nil {
						return err
					}
				}
			}
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
	entries, err := filepath.Glob(filepath.Join(m.BackupDir, "netos-*.tar.gz"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial backup still published: %v, %v", entries, err)
	}
}
