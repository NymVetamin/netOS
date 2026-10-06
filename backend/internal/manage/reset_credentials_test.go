package manage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Runtime cleanup tests replace systemctl; model the fresh daemon's credentials
// as well, so successful reset still exercises its complete contract.
func simulateResetCredentials(t *testing.T, m *Manager) {
	t.Helper()
	m.Sleep = func(time.Duration) {
		if err := os.WriteFile(filepath.Join(m.StateDir, "initial-credentials"), []byte("Пароль: test-password\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResetWaitsForCredentialsAfterSlowStartup(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	sleeps := 0
	m.Sleep = func(time.Duration) {
		sleeps++
		if sleeps == 100 {
			if err := os.WriteFile(filepath.Join(m.StateDir, "initial-credentials"), []byte("Пароль: delayed-password\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "delayed-password") {
		t.Fatalf("reset returned before credentials were printed (polls=%d)", sleeps)
	}
	if _, err := os.Stat(filepath.Join(m.StateDir, "initial-credentials")); !os.IsNotExist(err) {
		t.Fatalf("credentials remain: %v", err)
	}
}

func TestResetDoesNotReportSuccessWithoutCredentials(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	m.Sleep = func(time.Duration) {}
	if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err == nil {
		t.Fatal("reset reported success although no new credentials were created")
	}
	if strings.Contains(out.String(), "netOS сброшен.") {
		t.Fatal("premature success message")
	}
}

type failedCredentialsWriter struct{}

func (failedCredentialsWriter) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }

func TestCredentialsAreRetainedWhenTerminalWriteFails(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(m.StateDir, "initial-credentials")
	if err := os.WriteFile(filename, []byte("Пароль: not-displayed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.Out = failedCredentialsWriter{}
	if err := m.printCredentials(context.Background()); err == nil {
		t.Fatal("terminal error was ignored")
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatalf("undisplayed credentials were lost: %v", err)
	}
}

func TestCredentialWaitHonorsCancellation(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.printCredentials(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
