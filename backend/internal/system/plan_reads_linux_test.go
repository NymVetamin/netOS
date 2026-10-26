//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanUnitReadsScopeAndFallback(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("state", "active")
	write("systemctl", `#!/bin/sh
echo "$*" >> "$PLAN_READ_TEST/log"
state=$(cat "$PLAN_READ_TEST/state")
case "$1" in
 list-units)
  test -e "$PLAN_READ_TEST/fail" && exit 1
  echo "known.service loaded $state running Test"
  echo "failed.service loaded failed failed Test"
  echo "missing.service not-found inactive dead Test"
  echo "moving.service loaded activating start Test"
  ;;
 is-active)
  case "$2" in
   known.service) echo "$state"; test "$state" = active ;;
   *) echo original-fallback; exit 3 ;;
  esac ;;
 is-enabled)
  if test -e "$PLAN_READ_TEST/fail"; then echo probe-error >&2; exit 1; fi
  echo enabled ;;
 list-unit-files) echo "$3 enabled enabled" ;;
 *) echo passthrough ;;
esac
`)
	t.Setenv("PLAN_READ_TEST", dir)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	r := NewExec()
	ctx := WithPlanUnitReads(context.Background())
	for i := 0; i < 3; i++ {
		out, err := r.Run(ctx, "systemctl", "is-active", "known.service")
		if err != nil || strings.TrimSpace(out) != "active" {
			t.Fatalf("%q %v", out, err)
		}
		_, err = r.Run(ctx, "systemctl", "is-enabled", "known.service")
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Run(ctx, "systemctl", "list-unit-files", "--no-legend", "known.service")
		if err != nil {
			t.Fatal(err)
		}
	}
	log, _ := os.ReadFile(filepath.Join(dir, "log"))
	if strings.Count(string(log), "list-units ") != 1 || strings.Count(string(log), "is-enabled ") != 1 || strings.Count(string(log), "list-unit-files ") != 1 || strings.Contains(string(log), "is-active ") {
		t.Fatalf("not batched: %s", log)
	}
	for _, unit := range []string{"missing.service", "moving.service", "alias.service"} {
		out, err := r.Run(ctx, "systemctl", "is-active", unit)
		if err == nil || strings.TrimSpace(out) != "original-fallback" {
			t.Fatalf("fallback %s: %q %v", unit, out, err)
		}
	}
	out, err := r.Run(ctx, "systemctl", "is-active", "failed.service")
	if err == nil || strings.TrimSpace(out) != "failed" {
		t.Fatalf("failed: %q %v", out, err)
	}
	write("state", "inactive")
	out, err = r.Run(ctx, "systemctl", "is-active", "known.service")
	if err != nil || strings.TrimSpace(out) != "active" {
		t.Fatal("scope lost snapshot")
	}
	for _, fresh := range []context.Context{context.Background(), WithPlanUnitReads(ctx)} {
		out, err = r.Run(fresh, "systemctl", "is-active", "known.service")
		if err == nil || strings.TrimSpace(out) != "inactive" {
			t.Fatalf("stale next request: %q %v", out, err)
		}
	}
	// Distinct runners cannot consume each other's cached state.
	out, err = NewExec().Run(ctx, "systemctl", "is-active", "known.service")
	if err == nil || strings.TrimSpace(out) != "inactive" {
		t.Fatalf("runner isolation: %q %v", out, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = r.Run(cancelled, "systemctl", "is-active", "known.service")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	// Snapshot failure falls back, with original error text; failed queries retry.
	write("fail", "")
	broken := WithPlanUnitReads(context.Background())
	out, err = r.Run(broken, "systemctl", "is-active", "known.service")
	if err == nil || strings.TrimSpace(out) != "inactive" {
		t.Fatalf("snapshot failure: %q %v", out, err)
	}
	_, err = r.Run(broken, "systemctl", "is-enabled", "known.service")
	if err == nil || !strings.Contains(err.Error(), "probe-error") {
		t.Fatalf("error lost: %v", err)
	}
	if err = os.Remove(filepath.Join(dir, "fail")); err != nil {
		t.Fatal(err)
	}
	out, err = r.Run(broken, "systemctl", "is-enabled", "known.service")
	if err != nil || strings.TrimSpace(out) != "enabled" {
		t.Fatalf("retry: %q %v", out, err)
	}
	for _, args := range [][]string{{"restart", "known.service"}, {"is-active", "*.service"}, {"is-active", "known.service", "failed.service"}} {
		_, _, handled := r.planUnitRead(ctx, args)
		if handled {
			t.Fatalf("unexpected interception: %v", args)
		}
	}
}

// Explicitly enabled only on a disposable/authorized systemd test host.
func TestPlanUnitReadsRealSystemd(t *testing.T) {
	if os.Getenv("NETOS_PLAN_SYSTEMD_TEST") != "1" {
		t.Skip("requires authorized systemd host")
	}
	r := NewExec()
	plain := context.Background()
	units := []string{"netos-qa-plan-active.service", "netos-qa-plan-inactive.service", "netos-qa-plan-failed.service", "netos-qa-plan-static.service", "netos-qa-plan-alias.service", "netos-qa-plan-masked.service"}
	command := func(args ...string) {
		t.Helper()
		if out, err := r.Run(plain, "systemctl", args...); err != nil {
			t.Fatalf("%v: %q %v", args, out, err)
		}
	}
	for _, unit := range units {
		if _, err := os.Lstat("/run/systemd/system/" + unit); !os.IsNotExist(err) {
			t.Fatalf("fixture already exists: %s", unit)
		}
	}
	t.Cleanup(func() {
		for _, unit := range units {
			_, _ = r.Run(plain, "systemctl", "stop", unit)
			_, _ = r.Run(plain, "systemctl", "disable", "--runtime", unit)
			_ = os.Remove("/run/systemd/system/" + unit)
		}
		_, _ = r.Run(plain, "systemctl", "daemon-reload")
		for _, unit := range units {
			_, _ = r.Run(plain, "systemctl", "reset-failed", unit)
		}
	})
	for _, unit := range units[:4] {
		body := "[Service]\nExecStart=/bin/sleep 300\n"
		if strings.Contains(unit, "failed") {
			body = "[Service]\nType=oneshot\nExecStart=/bin/false\n"
		}
		if !strings.Contains(unit, "static") {
			body += "[Install]\nWantedBy=multi-user.target\n"
		}
		if err := os.WriteFile("/run/systemd/system/"+unit, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(units[0], "/run/systemd/system/"+units[4]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", "/run/systemd/system/"+units[5]); err != nil {
		t.Fatal(err)
	}
	command("daemon-reload")
	command("enable", "--runtime", units[0])
	command("start", units[0])
	_, _ = r.Run(plain, "systemctl", "start", units[2])
	compare := func() {
		t.Helper()
		ctx := WithPlanUnitReads(plain)
		for _, unit := range append(units, "netos-qa-plan-absent.service") {
			for _, verb := range []string{"is-active", "is-enabled", "list-unit-files"} {
				args := []string{verb}
				if verb == "list-unit-files" {
					args = append(args, "--no-legend")
				}
				args = append(args, unit)
				want, we := r.Run(plain, "systemctl", args...)
				got, ge := r.Run(ctx, "systemctl", args...)
				if strings.TrimSpace(got) != strings.TrimSpace(want) || (ge == nil) != (we == nil) {
					t.Errorf("%v: original=%q/%v snapshot=%q/%v", args, want, we, got, ge)
				}
			}
		}
	}
	compare()
	command("stop", units[0])
	command("disable", "--runtime", units[0])
	compare()
	command("enable", "--runtime", units[0])
	command("start", units[0])
	compare()
}
