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

func runManagedCommand(ctx context.Context, command func() *exec.Cmd, parent string, packageCommand bool) error {
	started, err := runInCommandGroup(ctx, command(), parent, packageCommand)
	// Restricted kernels can deny delegation or clone3. Preserve ordinary
	// commands on those hosts. Never repeat a command that actually started.
	if !started && !packageCommand && ctx.Err() == nil &&
		(errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EROFS) ||
			errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) ||
			errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP)) {
		return command().Run()
	}
	return err
}

func runInCommandGroup(ctx context.Context, cmd *exec.Cmd, parent string, packageCommand bool) (bool, error) {
	dir, err := os.MkdirTemp(parent, "apt-")
	if err != nil {
		return false, fmt.Errorf("создание группы команды: %w", err)
	}
	defer retirePackageGroup(dir)
	group, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer group.Close()
	events, err := os.Open(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		return false, err
	}
	defer events.Close()
	kill, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer kill.Close()
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
	// The supervisor below also handles cancellation after the leader exits.
	cmd.Cancel = nil
	if err = cmd.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitForOutput := true
	var commandErr error
	select {
	case commandErr = <-done:
		waitForOutput = false
		if ctx.Err() == nil {
			return true, commandErr
		}
	case <-ctx.Done():
	}
	if packageCommand {
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
	} else {
		_, err = kill.WriteString("1")
		if err == nil {
			err = waitPackageGroup(events)
		}
	}
	if waitForOutput {
		commandErr = <-done
	}
	if !packageCommand && commandErr == nil && err == nil {
		// Exec reports the expired context without repeating successful stdout.
		return true, nil
	}
	return true, errors.Join(ctx.Err(), err)
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
