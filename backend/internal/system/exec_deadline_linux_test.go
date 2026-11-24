package system

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

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
