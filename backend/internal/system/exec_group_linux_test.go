package system

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecTimeoutStopsDescendants(t *testing.T) {
	runner := NewExec()
	runner.Timeout = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The child prints its PID, then both wait; the timeout must end the pair.
	started := time.Now()
	out, err := runner.Run(ctx, "sh", "-c", `sleep 30 & echo $!; wait`)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(started))
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(out))
	if convErr != nil {
		t.Fatalf("child pid %q: %v", out, convErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d survived the timeout", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A successful command keeps its background helper.
	out, err = runner.Run(context.Background(), "sh", "-c", `sleep 2 </dev/null >/dev/null 2>&1 & echo $!`)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ = strconv.Atoi(strings.TrimSpace(out))
	if pid == 0 || syscall.Kill(pid, 0) != nil {
		t.Fatalf("helper of a successful command is gone: %q", out)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
