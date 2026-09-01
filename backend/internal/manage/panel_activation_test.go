package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func panelActivationFixture(t *testing.T) (*Manager, int64, int64) {
	t.Helper()
	m, _ := testManager()
	m.Root = t.TempDir()
	m.Database = "/var/lib/netos/netos.db"
	m.ReadyFile = "/run/netosd.ready"
	m.Sleep = func(_ time.Duration) {}
	if err := os.MkdirAll(filepath.Dir(m.sys(m.Database)), 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	previous, err := st.CreateRevision(config.Default(), "admin", "before panel change")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkActive(previous); err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Default()
	targetCfg.System.Panel.Port = 9443
	target, err := st.CreateRevision(targetCfg, "admin", "panel change")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRevisionState(target, store.StateApplying); err != nil {
		t.Fatal(err)
	}
	return m, target, previous
}

func TestInternalPanelActivationCommitsOnlyAfterReadyMarker(t *testing.T) {
	m, target, previous := panelActivationFixture(t)
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name != "systemctl" || strings.Join(cmd.args, " ") != "restart netosd" {
			return fmt.Errorf("unexpected command: %s %v", cmd.name, cmd.args)
		}
		if err := os.MkdirAll(filepath.Dir(m.sys(m.ReadyFile)), 0o755); err != nil {
			return err
		}
		return os.WriteFile(m.sys(m.ReadyFile), []byte(strconv.FormatInt(target, 10)+"\n"), 0o644)
	}
	if err := m.Execute(context.Background(), []string{"internal-panel-activate", strconv.FormatInt(target, 10), strconv.FormatInt(previous, 10)}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	active, err := st.ActiveRevision()
	if err != nil || active.ID != target {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}

func TestInternalPanelActivationRollsBackWhenTargetNeverBecomesReady(t *testing.T) {
	m, target, previous := panelActivationFixture(t)
	restarts := 0
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name != "systemctl" || strings.Join(cmd.args, " ") != "restart netosd" {
			return fmt.Errorf("unexpected command: %s %v", cmd.name, cmd.args)
		}
		restarts++
		if restarts == 2 {
			if err := os.MkdirAll(filepath.Dir(m.sys(m.ReadyFile)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(m.ReadyFile), []byte(strconv.FormatInt(previous, 10)+"\n"), 0o644)
		}
		return nil
	}
	err := m.Execute(context.Background(), []string{"internal-panel-activate", strconv.FormatInt(target, 10), strconv.FormatInt(previous, 10)})
	if err == nil || !strings.Contains(err.Error(), "предыдущая ревизия восстановлена") {
		t.Fatalf("error=%v", err)
	}
	if restarts != 2 {
		t.Fatalf("restart count=%d", restarts)
	}
	st, openErr := store.Open(m.sys(m.Database))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer st.Close()
	active, activeErr := st.ActiveRevision()
	rolled, rolledErr := st.Revision(target)
	if activeErr != nil || active.ID != previous || rolledErr != nil || rolled.State != store.StateRolledBack {
		t.Fatalf("active=%+v activeErr=%v target=%+v targetErr=%v", active, activeErr, rolled, rolledErr)
	}
}

func TestInternalPanelActivationDoesNotAcceptStaleRollbackMarker(t *testing.T) {
	m, target, previous := panelActivationFixture(t)
	if err := os.MkdirAll(filepath.Dir(m.sys(m.ReadyFile)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.sys(m.ReadyFile), []byte(strconv.FormatInt(previous, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	m.Run = func(_ context.Context, cmd command) error {
		if cmd.name != "systemctl" || strings.Join(cmd.args, " ") != "restart netosd" {
			return fmt.Errorf("unexpected command: %s %v", cmd.name, cmd.args)
		}
		restarts++
		if _, err := os.Stat(m.sys(m.ReadyFile)); !os.IsNotExist(err) {
			return fmt.Errorf("stale ready marker still exists before restart %d: %v", restarts, err)
		}
		return nil
	}
	err := m.Execute(context.Background(), []string{"internal-panel-activate", strconv.FormatInt(target, 10), strconv.FormatInt(previous, 10)})
	if err == nil || !strings.Contains(err.Error(), "запуск также не подтверждён") {
		t.Fatalf("error=%v", err)
	}
	if restarts != 2 {
		t.Fatalf("restart count=%d", restarts)
	}
}

func TestInternalPanelActivationRejectsInvalidArgumentsAndState(t *testing.T) {
	m, target, previous := panelActivationFixture(t)
	for _, args := range [][]string{
		{"internal-panel-activate"},
		{"internal-panel-activate", "bad", "1"},
		{"internal-panel-activate", "1", "1"},
	} {
		if err := m.Execute(context.Background(), args); err == nil {
			t.Fatalf("accepted args=%v", args)
		}
	}
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRevisionState(target, store.StateDraft); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if err := m.Execute(context.Background(), []string{"internal-panel-activate", strconv.FormatInt(target, 10), strconv.FormatInt(previous, 10)}); err == nil || !strings.Contains(err.Error(), "ожидалось applying") {
		t.Fatalf("invalid state error=%v", err)
	}
}

func TestACMEPanelActivationUsesIssuanceWindowAndFailsEarlyWithService(t *testing.T) {
	cfg := config.Default()
	if got := panelReadyAttempts(cfg); got != 60 {
		t.Fatalf("selfsigned attempts=%d", got)
	}
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.acme-valid.com", AcceptTOS: true}
	if got := panelReadyAttempts(cfg); got != 360 {
		t.Fatalf("ACME attempts=%d", got)
	}
	m, _ := testManager()
	sandbox(t, m)
	m.Run = func(context.Context, command) error { return nil }
	m.Output = func(context.Context, string, ...string) (string, error) { return "failed\n", nil }
	if err := m.restartAndWaitReady(context.Background(), 42, 360); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("failed service wait error=%v", err)
	}
}
