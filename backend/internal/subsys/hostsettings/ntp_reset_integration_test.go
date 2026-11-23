//go:build linux

package hostsettings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// This test changes timesyncd settings on an explicitly disposable systemd host.
func TestIntegrationNTPReplacesEarlierServers(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("explicit disposable root integration only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runner := system.NewExec()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := runner.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return strings.TrimSpace(out)
	}
	const unit = "systemd-timesyncd.service"
	active, _ := runner.Run(ctx, "systemctl", "is-active", unit)
	enabled, _ := runner.Run(ctx, "systemctl", "is-enabled", unit)
	if state := strings.TrimSpace(enabled); state != "enabled" && state != "disabled" {
		t.Fatalf("test requires installed, unmasked timesyncd: %q", state)
	}
	s := New(runner)
	early := "/run/systemd/timesyncd.conf.d/80-netos-test.conf"
	for _, path := range []string{early, s.TimesyncdPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusing existing or unreadable test path: %s (%v)", path, err)
		}
	}
	t.Cleanup(func() {
		for _, path := range []string{early, s.TimesyncdPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		autostart, running := "disable", "stop"
		if strings.TrimSpace(enabled) == "enabled" {
			autostart = "enable"
		}
		if strings.TrimSpace(active) == "active" {
			running = "restart"
		}
		for _, action := range []string{autostart, running} {
			if out, err := runner.Run(cleanup, "systemctl", action, unit); err != nil {
				t.Errorf("restore %s: %v %s", action, err, out)
			}
		}
	})
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(early, []byte("[Time]\nNTP=\nNTP=192.0.2.99\n"))
	cfg := config.Default()
	cfg.System.NTP.Enabled = true
	cfg.System.NTP.Servers = []string{"192.0.2.10", "192.0.2.11"}
	// Reproduce the previously generated file in the real daemon first.
	write(s.TimesyncdPath, []byte("[Time]\nNTP=192.0.2.10 192.0.2.11\nFallbackNTP=\n"))
	run("systemctl", "restart", unit)
	read := func() string { return run("timedatectl", "show-timesync", "--property=SystemNTPServers", "--value") }
	if got := read(); got != "192.0.2.99 192.0.2.10 192.0.2.11" {
		t.Fatalf("legacy reproduction=%q", got)
	}
	t.Log("legacy file retains earlier NTP server")
	for _, servers := range [][]string{{"192.0.2.10", "192.0.2.11"}, {"192.0.2.12"}} {
		cfg.System.NTP.Servers = servers
		if err := s.applyNTP(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if got := read(); got != strings.Join(servers, " ") {
			t.Fatalf("live servers=%q want=%v", got, servers)
		}
		if match, err := s.ntpServersMatch(ctx, cfg); err != nil || !match {
			t.Fatalf("health check match=%v err=%v", match, err)
		}
		invocation := run("systemctl", "show", unit, "--property=InvocationID", "--value")
		if invocation == "" {
			t.Fatal("missing InvocationID")
		}
		for range 2 {
			if err := s.applyNTP(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			if got := run("systemctl", "show", unit, "--property=InvocationID", "--value"); got != invocation {
				t.Fatal("repeat restarted daemon")
			}
		}
	}
	t.Log("real NTP replacement, changed list and idempotent repeats PASS")
}
