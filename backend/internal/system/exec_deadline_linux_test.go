package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommandCancellationStopsDescendants(t *testing.T) {
	if os.Getenv("NETOS_PACKAGE_CGROUP") == "" {
		t.Skip("requires a delegated test cgroup")
	}
	for _, parent := range []string{"wait", "exit 0"} {
		t.Run(parent, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("QA_EVENTS", filepath.Join(dir, "events"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := NewExec().Run(ctx, "sh", "-c",
					`setsid sh -c 'echo ready >"$QA_EVENTS"; sleep 1; echo late >>"$QA_EVENTS"' & `+parent)
				done <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				data, _ := os.ReadFile(os.Getenv("QA_EVENTS"))
				if string(data) == "ready\n" {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("command exited before child started: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("child did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			time.Sleep(1100 * time.Millisecond)
			if data, err := os.ReadFile(os.Getenv("QA_EVENTS")); err != nil || string(data) != "ready\n" {
				t.Fatalf("surviving descendant: %q, %v", data, err)
			}
		})
	}
	t.Run("successful parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events")
		t.Setenv("QA_EVENTS", path)
		out, err := NewExec().Run(context.Background(), "sh", "-c",
			`(sleep 0.1; echo finished >"$QA_EVENTS") </dev/null >/dev/null 2>&1 & printf started`)
		if err != nil || out != "started" {
			t.Fatalf("start: %q %v", out, err)
		}
		until := time.Now().Add(3 * time.Second)
		for time.Now().Before(until) {
			if data, _ := os.ReadFile(path); string(data) == "finished\n" {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("successful command lost its background helper")
	})
}

func TestCommandWithoutDelegation(t *testing.T) {
	t.Setenv("NETOS_PACKAGE_CGROUP", filepath.Join(t.TempDir(), "missing"))
	r := NewExec()
	out, err := r.RunInput(context.Background(), "first\n", "sh", "-c", "read -r line; echo \"$line\"; echo failed >&2; exit 8")
	if out != "first\n" || err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("output %q, error %v", out, err)
	}
	out, err = r.Run(context.Background(), "sh", "-c", "printf retry")
	if out != "retry" || err != nil {
		t.Fatalf("retry %q, error %v", out, err)
	}
}

func TestExecDeadlineWhileDrainingOutput(t *testing.T) {
	runner := NewExec()
	runner.Timeout = 500 * time.Millisecond
	// The shell exits successfully while its child still holds the output pipe.
	out, err := runner.RunInput(context.Background(), "command-output\n", "sh", "-c",
		"read -r line; printf '%s' \"$line\"; sleep 1 &")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline expired while draining output: err=%v", err)
	}
	if out != "command-output" || strings.Contains(err.Error(), out) {
		t.Fatalf("unexpected output or diagnostic: out=%q err=%v", out, err)
	}
	out, err = runner.Run(context.Background(), "sh", "-c", "printf retry")
	if err != nil || out != "retry" {
		t.Fatalf("fresh command: out=%q err=%v", out, err)
	}
}
