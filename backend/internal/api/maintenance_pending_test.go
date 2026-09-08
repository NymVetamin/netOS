package api

import (
	"context"
	"strings"
	"testing"
)

type pendingMaintenanceRunner struct{ timer, service string }

func (r pendingMaintenanceRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	if strings.Contains(strings.Join(args, " "), ".timer") {
		return r.timer, nil
	}
	return r.service, nil
}

func (r pendingMaintenanceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestMaintenanceStatusPendingTimer(t *testing.T) {
	for _, tc := range []struct {
		name, timer, service, state string
		failed                      bool
	}{
		{"first scheduled job", "ActiveState=active\nSubState=waiting\n", "", "activating", false},
		{"scheduled after failure", "ActiveState=active\nSubState=waiting\n", "ActiveState=failed\nResult=exit-code\nExecMainStatus=17\n", "activating", false},
		{"starting timer", "ActiveState=activating\n", "ActiveState=inactive\n", "activating", false},
		{"running service", "ActiveState=active\nSubState=elapsed\n", "ActiveState=active\nSubState=running\n", "active", false},
		{"completed service", "ActiveState=active\nSubState=elapsed\n", "ActiveState=inactive\nResult=success\n", "inactive", false},
		{"failed service", "ActiveState=inactive\nSubState=dead\n", "ActiveState=failed\nResult=exit-code\n", "failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Maintenance{Runner: pendingMaintenanceRunner{tc.timer, tc.service}, Unit: "netos-maintenance"}
			got := m.Status(context.Background())
			if got["state"] != tc.state || got["failed"] != tc.failed {
				t.Fatalf("status = %v; want state %s, failed %v", got, tc.state, tc.failed)
			}
		})
	}
}
