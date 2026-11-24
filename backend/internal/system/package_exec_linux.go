package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// waitPackageGroup waits for the kernel notification, including descendants
// that changed session or process group. No periodic cgroup scan is needed.
func waitPackageGroup(events *os.File) error {
	var buf [128]byte
	fds := []unix.PollFd{{Fd: int32(events.Fd()), Events: unix.POLLPRI}}
	for {
		n, err := events.ReadAt(buf[:], 0)
		if n == 0 {
			return err
		}
		if strings.Contains("\n"+string(buf[:n]), "\npopulated 0\n") {
			return nil
		}
		if _, err = unix.Poll(fds, -1); err != nil && err != unix.EINTR {
			return err
		}
	}
}

func runPackageCommand(ctx context.Context, cmd *exec.Cmd, parent string) error {
	dir, err := os.MkdirTemp(parent, "apt-")
	if err != nil {
		return fmt.Errorf("создание группы пакетной операции: %w", err)
	}
	defer retirePackageGroup(dir)
	group, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer group.Close()
	events, err := os.Open(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		return err
	}
	defer events.Close()
	kill, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer kill.Close()
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
	// The supervisor below also handles cancellation after the leader exits.
	cmd.Cancel = nil
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitForOutput := true
	select {
	case err = <-done:
		waitForOutput = false
		if ctx.Err() == nil {
			return err
		}
	case <-ctx.Done():
	}
	_ = cmd.Process.Signal(os.Interrupt)
	empty := make(chan error, 1)
	go func() { empty <- waitPackageGroup(events) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err = <-empty:
	case <-timer.C:
		_, killErr := kill.WriteString("1")
		err = errors.Join(killErr, <-empty)
	}
	if waitForOutput {
		<-done
	}
	return errors.Join(ctx.Err(), err)
}

// A package can successfully start a helper. Leave its limits in place and
// remove the temporary group when the kernel reports its last process exited.
func retirePackageGroup(dir string) {
	if err := os.Remove(dir); !errors.Is(err, syscall.EBUSY) {
		return
	}
	events, err := os.Open(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		return
	}
	go func() {
		defer events.Close()
		if waitPackageGroup(events) == nil {
			_ = os.Remove(dir)
		}
	}()
}

// stopGroupOnCancel puts the command in its own process group and kills the
// whole group on timeout or cancellation, so its helpers do not outlive it.
// WaitDelay bounds the wait for a descendant that left the group but still
// holds the output pipes. A successful command's background helpers survive.
func stopGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
}
