package xraylog

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Run keeps the child's stdout/stderr out of the journal until sanitized.
// A broken log sink terminates the child instead of silently disabling logs.
func Run(ctx context.Context, executable string, args []string, out io.Writer) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := newStream(out, cancel)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Cancel = func() error {
		err := cmd.Process.Signal(syscall.SIGTERM)
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return cmd.Process.Kill()
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	// A sink failure is the cause, not the cancellation it triggered. Keeping
	// these distinct also prevents a normal service stop from hiding log errors.
	if outputErr := w.Close(); outputErr != nil {
		return outputErr
	}
	if parent.Err() != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGTERM {
				return parent.Err()
			}
		}
	}
	return err
}
