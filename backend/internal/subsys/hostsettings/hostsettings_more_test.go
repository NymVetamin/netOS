package hostsettings

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func writeExpectedNTP(t *testing.T, s *Subsystem, cfg *config.Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(s.TimesyncdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(s.TimesyncdPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.TimesyncdPath, s.renderNTP(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasCommand(commands []string, wanted string) bool {
	for _, command := range commands {
		if command == wanted {
			return true
		}
	}
	return false
}

func TestNameAndPlanUseLiveStateIncludingInitialPlan(t *testing.T) {
	cfg := config.Default()
	cfg.System.Hostname = "router"
	cfg.System.Timezone = "Europe/Moscow"

	matchingRunner := &hostRunner{}
	matching := testSubsystem(t, matchingRunner)
	writeExpectedNTP(t, matching, cfg)
	if matching.Name() != "system" {
		t.Fatalf("Name=%q", matching.Name())
	}
	actions, err := matching.Plan(nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("initial live-matching plan is dirty: %#v", actions)
	}

	driftRunner := &hostRunner{host: "other", timezone: "UTC"}
	drift := testSubsystem(t, driftRunner)
	actions, err = drift.Plan(cfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, action := range actions {
		joined += action.Target + "\n"
	}
	for _, target := range []string{"имя хоста", "часовой пояс", "синхронизация времени"} {
		if !strings.Contains(joined, target) {
			t.Fatalf("live drift %q missing from plan: %#v", target, actions)
		}
	}
}

func TestApplyIsIdempotentWhenLiveStateMatches(t *testing.T) {
	runner := &hostRunner{}
	s := testSubsystem(t, runner)
	cfg := config.Default()
	cfg.System.Hostname = "router"
	cfg.System.Timezone = "Europe/Moscow"
	writeExpectedNTP(t, s, cfg)
	before, err := os.Stat(s.TimesyncdPath)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(s.TimesyncdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("unchanged NTP file was rewritten: before=%s after=%s", before.ModTime(), after.ModTime())
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " set-hostname ") || strings.Contains(command, " set-timezone ") ||
			command == "systemctl enable --now systemd-timesyncd.service" ||
			command == "systemctl restart systemd-timesyncd.service" {
			t.Fatalf("idempotent Apply mutated live state: %s", command)
		}
	}
}

func TestApplyNTPTransitionMatrix(t *testing.T) {
	tests := []struct {
		name         string
		active       string
		enabled      string
		matchingFile bool
		wantEnable   bool
		wantRestart  bool
	}{
		{name: "changed active enabled", active: "active", enabled: "enabled", wantRestart: true},
		{name: "changed inactive enabled", active: "inactive", enabled: "enabled", wantEnable: true},
		{name: "changed active disabled", active: "active", enabled: "disabled", wantEnable: true, wantRestart: true},
		{name: "same active disabled", active: "active", enabled: "disabled", matchingFile: true, wantEnable: true},
		{name: "same inactive enabled", active: "inactive", enabled: "enabled", matchingFile: true, wantEnable: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &hostRunner{timesyncActive: tc.active, timesyncEnabled: tc.enabled}
			s := testSubsystem(t, runner)
			cfg := config.Default()
			if tc.matchingFile {
				writeExpectedNTP(t, s, cfg)
			}
			if err := s.applyNTP(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			gotEnable := hasCommand(runner.commands, "systemctl enable --now systemd-timesyncd.service")
			gotRestart := hasCommand(runner.commands, "systemctl restart systemd-timesyncd.service")
			if gotEnable != tc.wantEnable || gotRestart != tc.wantRestart {
				t.Fatalf("commands=%v; enable=%v/%v restart=%v/%v", runner.commands, gotEnable, tc.wantEnable, gotRestart, tc.wantRestart)
			}
			if changed := systemFileChanged(s.TimesyncdPath, s.renderNTP(cfg)); changed {
				t.Fatal("NTP file does not match rendered configuration")
			}
		})
	}
}

func systemFileChanged(path string, expected []byte) bool {
	data, err := os.ReadFile(path)
	return err != nil || string(data) != string(expected)
}

func TestApplyNTPDisableAndCleanDisabledNoop(t *testing.T) {
	cfg := config.Default()
	cfg.System.NTP.Enabled = false

	runner := &hostRunner{timesyncActive: "active", timesyncEnabled: "enabled"}
	s := testSubsystem(t, runner)
	writeExpectedNTP(t, s, config.Default())
	if err := s.applyNTP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.TimesyncdPath); !os.IsNotExist(err) {
		t.Fatalf("disabled NTP config remains: %v", err)
	}
	if !hasCommand(runner.commands, "systemctl disable systemd-timesyncd.service") ||
		!hasCommand(runner.commands, "systemctl stop systemd-timesyncd.service") {
		t.Fatalf("timesyncd was not disabled and stopped: %v", runner.commands)
	}

	cleanRunner := &hostRunner{timesyncActive: "inactive", timesyncEnabled: "disabled"}
	clean := testSubsystem(t, cleanRunner)
	if err := clean.applyNTP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range cleanRunner.commands {
		if command == "systemctl disable systemd-timesyncd.service" || command == "systemctl stop systemd-timesyncd.service" {
			t.Fatalf("clean disabled NTP was mutated: %v", cleanRunner.commands)
		}
	}
}

type failingHostRunner struct {
	base *hostRunner
	fail string
}

func (r *failingHostRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if command == r.fail {
		return "", errors.New("injected failure")
	}
	return r.base.Run(ctx, name, args...)
}

func (r *failingHostRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestApplyPropagatesCommandFailures(t *testing.T) {
	tests := []struct {
		name   string
		base   *hostRunner
		fail   string
		needle string
	}{
		{name: "contending daemon", base: &hostRunner{active: true}, fail: "systemctl disable tuned.service", needle: "tuned.service"},
		{name: "hostname", base: &hostRunner{host: "old"}, fail: "hostnamectl set-hostname router", needle: "имени хоста"},
		{name: "timezone", base: &hostRunner{timezone: "UTC"}, fail: "timedatectl set-timezone Europe/Moscow", needle: "часового пояса"},
		{name: "timesync enable", base: &hostRunner{timesyncActive: "inactive", timesyncEnabled: "disabled"}, fail: "systemctl enable --now systemd-timesyncd.service", needle: "синхронизации времени"},
		{name: "timesync restart", base: &hostRunner{}, fail: "systemctl restart systemd-timesyncd.service", needle: "синхронизации времени"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &failingHostRunner{base: tc.base, fail: tc.fail}
			s := New(runner)
			s.TimesyncdPath = filepath.Join(t.TempDir(), "90-netos.conf")
			cfg := config.Default()
			cfg.System.Hostname = "router"
			cfg.System.Timezone = "Europe/Moscow"
			err := s.Apply(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("failure %q hidden: %v", tc.fail, err)
			}
		})
	}
}

func TestHealthFailureMatrixAndDisabledSuccess(t *testing.T) {
	tests := []struct {
		name       string
		base       *hostRunner
		fail       string
		prepareNTP bool
		needle     string
	}{
		{name: "hostname query", base: &hostRunner{}, fail: "hostnamectl --static", needle: "injected failure"},
		{name: "hostname mismatch", base: &hostRunner{host: "other"}, needle: "имя хоста"},
		{name: "timezone query", base: &hostRunner{}, fail: "timedatectl show --property=Timezone --value", needle: "injected failure"},
		{name: "timezone mismatch", base: &hostRunner{timezone: "UTC"}, needle: "часовой пояс"},
		{name: "NTP inactive", base: &hostRunner{timesyncActive: "inactive"}, prepareNTP: true, needle: "синхронизация времени"},
		{name: "NTP servers query", base: &hostRunner{}, fail: "timedatectl show-timesync --property=SystemNTPServers --value", prepareNTP: true, needle: "серверов времени"},
		{name: "NTP servers mismatch", base: &hostRunner{ntpServers: "wrong.example"}, prepareNTP: true, needle: "не прочитал"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var runner interface {
				Run(context.Context, string, ...string) (string, error)
				RunInput(context.Context, string, string, ...string) (string, error)
			} = tc.base
			if tc.fail != "" {
				runner = &failingHostRunner{base: tc.base, fail: tc.fail}
			}
			s := New(runner)
			s.TimesyncdPath = filepath.Join(t.TempDir(), "90-netos.conf")
			cfg := config.Default()
			cfg.System.Hostname = "router"
			cfg.System.Timezone = "Europe/Moscow"
			if tc.prepareNTP {
				writeExpectedNTP(t, s, cfg)
			}
			err := s.Health(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("Health failure hidden: %v", err)
			}
		})
	}

	runner := &hostRunner{timesyncActive: "inactive", timesyncEnabled: "disabled"}
	s := testSubsystem(t, runner)
	cfg := config.Default()
	cfg.System.Hostname = "router"
	cfg.System.Timezone = "Europe/Moscow"
	cfg.System.NTP.Enabled = false
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("clean disabled NTP unhealthy: %v", err)
	}
}

func TestNTPDirectoryPermissionDriftIsRepairedWithoutRestart(t *testing.T) {
	runner := &hostRunner{}
	s := testSubsystem(t, runner)
	cfg := config.Default()
	writeExpectedNTP(t, s, cfg)
	if err := os.Chmod(filepath.Dir(s.TimesyncdPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if s.timesyncdDirReady() {
		t.Skip("filesystem does not expose Unix directory permission changes")
	}
	if !s.ntpDrift(context.Background(), cfg) {
		t.Fatal("unreadable timesyncd directory was not drift")
	}
	if err := s.applyNTP(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(s.TimesyncdPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o555 != 0o555 {
		t.Fatalf("directory permissions not repaired: %v", info.Mode().Perm())
	}
	if hasCommand(runner.commands, "systemctl restart systemd-timesyncd.service") {
		t.Fatalf("permission-only repair restarted timesyncd: %v", runner.commands)
	}
}

func TestApplyNTPFilesystemAndDisableFailures(t *testing.T) {
	t.Run("remove nonempty path", func(t *testing.T) {
		runner := &hostRunner{timesyncActive: "inactive", timesyncEnabled: "disabled"}
		s := testSubsystem(t, runner)
		if err := os.Mkdir(s.TimesyncdPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.TimesyncdPath, "child"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Default()
		cfg.System.NTP.Enabled = false
		if err := s.applyNTP(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "удаление") {
			t.Fatalf("remove failure hidden: %v", err)
		}
	})

	t.Run("parent is a file", func(t *testing.T) {
		runner := &hostRunner{}
		s := New(runner)
		parent := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.TimesyncdPath = filepath.Join(parent, "90-netos.conf")
		if err := s.applyNTP(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "каталог") {
			t.Fatalf("mkdir failure hidden: %v", err)
		}
	})

	t.Run("target is a directory", func(t *testing.T) {
		runner := &hostRunner{}
		s := testSubsystem(t, runner)
		if err := os.Mkdir(s.TimesyncdPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := s.applyNTP(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "настройка") {
			t.Fatalf("write failure hidden: %v", err)
		}
	})

	t.Run("disable command", func(t *testing.T) {
		base := &hostRunner{timesyncActive: "active", timesyncEnabled: "enabled"}
		runner := &failingHostRunner{base: base, fail: "systemctl disable systemd-timesyncd.service"}
		s := New(runner)
		s.TimesyncdPath = filepath.Join(t.TempDir(), "90-netos.conf")
		cfg := config.Default()
		cfg.System.NTP.Enabled = false
		if err := s.applyNTP(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "отключение") {
			t.Fatalf("disable failure hidden: %v", err)
		}
	})
}

type fixedOutputRunner struct {
	output string
	err    error
}

func (r fixedOutputRunner) Run(context.Context, string, ...string) (string, error) {
	return r.output, r.err
}

func (r fixedOutputRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestUnitEnabledRecognizesAllSystemdStates(t *testing.T) {
	for _, state := range []string{"enabled", "enabled-runtime", "static", "indirect", "generated", "alias"} {
		s := New(fixedOutputRunner{output: state + "\n"})
		if !s.unitEnabled(context.Background(), "x.service") {
			t.Errorf("state %q was not enabled", state)
		}
	}
	for _, runner := range []fixedOutputRunner{{output: "disabled\n"}, {err: errors.New("failed")}} {
		s := New(runner)
		if s.unitEnabled(context.Background(), "x.service") {
			t.Errorf("state output=%q err=%v was enabled", runner.output, runner.err)
		}
	}
}
