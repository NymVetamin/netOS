package system

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type awgUnitRunner struct {
	commands        []string
	active, enabled bool
	fail            string
}

func (r *awgUnitRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, c)
	if strings.Contains(c, r.fail) && r.fail != "" {
		return "", errors.New("injected")
	}
	if args[0] == "is-active" && r.active {
		return "active", nil
	}
	if args[0] == "is-enabled" && r.enabled {
		return "enabled", nil
	}
	if args[0] == "restart" {
		r.active = true
	}
	if args[0] == "enable" {
		r.enabled = true
	}
	return "", nil
}
func (r *awgUnitRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestAmneziaWGServiceLifecycle(t *testing.T) {
	unit, err := RenderAmneziaWGUnit("awg-ch1", "/var/lib/netos/generated/channels/awg-ch1.conf", "10.1.0.2/32", 1420, 1001, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"Type=notify", "syncconf awg-ch1", "disable_ipv6=1", "addr replace 10.1.0.2/32", "table 1001", "Restart=on-failure"} {
		if !strings.Contains(string(unit), part) {
			t.Fatalf("missing %s", part)
		}
	}
	r := &awgUnitRunner{}
	dir := t.TempDir()
	ctx := context.Background()
	if err := EnsureAmneziaWGService(ctx, r, dir, "awg-ch1", unit); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := EnsureAmneziaWGService(ctx, r, dir, "awg-ch1", unit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.commands, "\n"), "restart") || len(r.commands) != 2 {
		t.Fatalf("unchanged service mutated: %v", r.commands)
	}
	r.active = false
	r.fail = "restart"
	if err := EnsureAmneziaWGService(ctx, r, dir, "awg-ch1", unit); err == nil {
		t.Fatal("startup error lost")
	}
	r.fail = ""
	if err := EnsureAmneziaWGService(ctx, r, dir, "awg-ch1", unit); err != nil || !r.active {
		t.Fatal("retry failed", err)
	}
	changed, err := RenderAmneziaWGUnit("awg-ch1", "/var/lib/netos/generated/channels/awg-ch1.conf", "10.2.0.2/32", 1380, 1001, false)
	if err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := EnsureAmneziaWGService(ctx, r, dir, "awg-ch1", changed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.commands, "\n"), "restart") {
		t.Fatal("changed addressing did not restart")
	}
}

func TestAmneziaWGUnitRejectsInjection(t *testing.T) {
	for _, path := range []string{"/tmp/x\nExecStart=/bin/false", "/tmp/$X", "/tmp/%i", "relative", "/tmp/x y", "/tmp/\"x"} {
		if _, err := RenderAmneziaWGUnit("awg-ch1", path, "10.0.0.2/32", 1420, 1001, false); err == nil {
			t.Fatal("unsafe unit path accepted")
		}
	}
}
