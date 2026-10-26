//go:build linux

package apply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type unitReadPlanSubsystem struct {
	runner *system.Exec
	state  string
}

func (s *unitReadPlanSubsystem) Name() string { return "interfaces" }
func (s *unitReadPlanSubsystem) Plan(a, b *config.Config) ([]Action, error) {
	return s.PlanContext(context.Background(), a, b)
}
func (s *unitReadPlanSubsystem) PlanContext(ctx context.Context, _, _ *config.Config) ([]Action, error) {
	for i := 0; i < 2; i++ {
		if out, err := s.runner.Run(ctx, "systemctl", "is-active", "test.service"); err != nil || strings.TrimSpace(out) != "active" {
			return nil, fmt.Errorf("plan state: %q %v", out, err)
		}
	}
	return nil, nil
}
func (s *unitReadPlanSubsystem) Apply(ctx context.Context, _ *config.Config) error {
	if err := os.WriteFile(s.state, []byte("inactive"), 0600); err != nil {
		return err
	}
	return s.Health(ctx, nil)
}
func (s *unitReadPlanSubsystem) Health(ctx context.Context, _ *config.Config) error {
	out, err := s.runner.Run(ctx, "systemctl", "is-active", "test.service")
	if err == nil || strings.TrimSpace(out) != "inactive" {
		return fmt.Errorf("plan snapshot leaked into apply/health: %q %v", out, err)
	}
	return nil
}

func TestPlanUnitSnapshotDoesNotLeakIntoApplyOrHealth(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.WriteFile(state, []byte("active"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
state=$(cat "$PLAN_APPLY_STATE")
case "$1" in
 list-units) echo "test.service loaded $state running Test" ;;
 is-active) echo "$state"; test "$state" = active ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PLAN_APPLY_STATE", state)
	e := NewEngine(testLogger{}, false)
	if err := e.Register(&unitReadPlanSubsystem{runner: system.NewExec(), state: state}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("scope-test"), 1, false); err != nil {
		t.Fatal(err)
	}
}
