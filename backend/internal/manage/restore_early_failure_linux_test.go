package manage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrationRestoreEarlyStartFailure(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("explicit integration only")
	}
	// No unit is created or altered: systemd must report this unique name absent.
	unit := "netos-restore-refusal-" + filepath.Base(t.TempDir()) + fmt.Sprint(os.Getpid()) + ".service"
	state, err := exec.Command("systemctl", "show", unit, "-p", "LoadState", "--value").CombinedOutput()
	if err != nil || strings.TrimSpace(string(state)) != "not-found" {
		t.Fatalf("unexpected fixture unit: %q %v", state, err)
	}
	checkRestoreEarlyStartFailure(t, func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "systemctl", "start", unit).CombinedOutput()
		if err == nil {
			t.Fatal("systemd accepted absent unit")
		}
		return fmt.Errorf("systemctl start fixture: %w: %s", err, strings.TrimSpace(string(out)))
	})
	t.Log("both early failures preserve real systemctl refusal and original state; retry PASS")
}
