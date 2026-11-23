package manage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestBackupHandlesInterruptDuringArchive(t *testing.T) {
	if os.Getenv("NETOS_TEST_BACKUP_INTERRUPT") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBackupHandlesInterruptDuringArchive$")
		cmd.Env = append(os.Environ(), "NETOS_TEST_BACKUP_INTERRUPT=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("interrupted backup: %v, %s", err, out)
		}
		return
	}
	m, _ := testManager()
	sandbox(t, m)
	seedBackupDatabase(t, m)
	started := false
	m.Run = func(ctx context.Context, cmd command) error {
		if cmd.name == "tar" {
			if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}
		if cmd.name == "systemctl" && cmd.args[0] == "start" {
			started = ctx.Err() == nil
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"backup"}); !errors.Is(err, context.Canceled) || !started {
		t.Fatalf("start=%v error=%v", started, err)
	}
}
