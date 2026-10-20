//go:build linux

package api

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

// Opt-in: creates only its own transient units on an authorized systemd host.
func TestMaintenanceRealSystemdLifecycle(t *testing.T) {
	if os.Getenv("NETOS_TEST_SYSTEMD_MAINTENANCE") != "1" {
		t.Skip("requires an authorized systemd test host")
	}
	ctx := context.Background()
	runner := &system.Exec{Timeout: 10 * time.Second}
	unit := fmt.Sprintf("netos-qa-maintenance-%d", os.Getpid())
	m := Maintenance{Runner: runner, Unit: unit}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, "systemctl", "stop", unit+"[.]timer", unit+"[.]service")
		_, _ = runner.Run(ctx, "systemctl", "reset-failed", unit+"[.]service")
	})
	waitState := func(want string) map[string]any {
		t.Helper()
		until := time.Now().Add(20 * time.Second)
		for {
			got := m.Status(ctx)
			if got["state"] == want {
				return got
			}
			if time.Now().After(until) {
				t.Fatalf("want %s, got %v", want, got)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err := m.scheduleCommand(ctx, []string{"/bin/sleep", "3"}); err != nil {
		t.Fatal(err)
	}
	waitState("activating")
	waitState("active")
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	waitState("idle")
	for i := 0; i < 15; i++ {
		if got := m.Status(ctx); got["state"] != "idle" {
			t.Fatalf("completed job: %v", got)
		}
	}
	log, err := runner.Run(ctx, "journalctl", "--no-pager", "-o", "cat",
		"-u", unit+".timer", "-u", unit+".service")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log, "Failed to open") {
		t.Fatalf("status polling produced systemd errors: %s", log)
	}
	if err := m.scheduleCommand(ctx, []string{"/bin/sh", "-c", "exit 17"}); err != nil {
		t.Fatal(err)
	}
	got := waitState("failed")
	if got["failed"] != true || got["exit_code"] != "17" {
		t.Fatalf("failure hidden: %v", got)
	}
	if err := m.scheduleCommand(ctx, []string{"/bin/true"}); err != nil {
		t.Fatal(err)
	}
	waitState("activating")
	waitState("idle")
}
