package manage

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestBackupCannotInterruptRestore(t *testing.T) {
	root := t.TempDir()
	first, second := New("test"), New("test")
	for _, m := range []*Manager{first, second} {
		m.Root, m.Out, m.Err = root, io.Discard, io.Discard
		m.EUID = func() int { return 0 }
		m.Output = func(context.Context, string, ...string) (string, error) { return "active\n", nil }
	}
	stop := errors.New("stop at mutation boundary")
	secondMutated := false
	second.Run = func(context.Context, command) error {
		secondMutated = true
		return stop
	}
	first.Run = func(context.Context, command) error {
		if err := second.Execute(context.Background(), []string{"backup"}); err == nil {
			t.Error("concurrent backup accepted")
		}
		if secondMutated {
			t.Error("backup reached system mutation while restore was in progress")
		}
		return stop
	}
	archive := writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/", Typeflag: tar.TypeDir, Mode: 0o700}})
	if err := first.Execute(context.Background(), []string{"restore", archive, "--yes"}); err == nil {
		t.Fatal("injected restore failure lost")
	}
	secondMutated = false
	_ = second.Execute(context.Background(), []string{"backup"})
	if !secondMutated {
		t.Fatal("failed restore did not release maintenance ownership")
	}
}

func TestMaintenanceLockAcrossProcesses(t *testing.T) {
	if root := os.Getenv("NETOS_QA_LOCK_ROOT"); root != "" {
		m := New("test")
		m.Root = root
		release, err := m.lockMaintenance()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		fmt.Fprintln(os.Stdout, "locked")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	m := New("test")
	m.Root = t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMaintenanceLockAcrossProcesses$")
	child.Env = append(os.Environ(), "NETOS_QA_LOCK_ROOT="+m.Root)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child readiness: %q (%v)", line, err)
	}
	if release, err := m.lockMaintenance(); err == nil {
		release()
		t.Fatal("another process acquired the maintenance lock")
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	release, err := m.lockMaintenance()
	if err != nil {
		t.Fatalf("killed process left a stale lock: %v", err)
	}
	release()
}
