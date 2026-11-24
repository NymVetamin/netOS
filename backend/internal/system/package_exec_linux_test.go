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

// Run in the disposable installer guest with its real delegated cgroup.
func TestPackageCancellationStopsDetachedChild(t *testing.T) {
	parent := os.Getenv("NETOS_PACKAGE_CGROUP")
	if parent == "" {
		t.Skip("requires a delegated test cgroup")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("QA_EVENTS", filepath.Join(dir, "events"))
	script := `#!/bin/sh
set -eu
case "$1" in
 success) printf done; exit 0;;
 failure) echo 'package failure' >&2; exit 7;;
esac
trap 'exit 0' INT
setsid sh -c 'trap "" INT TERM; echo ready >"$QA_EVENTS"; sleep 14; echo late >>"$QA_EVENTS"' &
wait
`
	if err := os.WriteFile(filepath.Join(dir, "apt-get"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	r := NewExec()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Run(ctx, "apt-get", "wait"); done <- err }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, _ := os.ReadFile(os.Getenv("QA_EVENTS"))
		if string(data) == "ready\n" {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("package exited before child started: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("package did not stop")
	}
	if time.Since(start) < 9*time.Second {
		t.Fatal("grace period was skipped")
	}
	time.Sleep(4500 * time.Millisecond)
	data, err := os.ReadFile(os.Getenv("QA_EVENTS"))
	if err != nil || string(data) != "ready\n" {
		t.Fatalf("late child action: %q, %v", data, err)
	}
	if _, err := r.Run(context.Background(), "apt-get", "failure"); err == nil || !strings.Contains(err.Error(), "package failure") {
		t.Fatalf("package error: %v", err)
	}
	if out, err := r.Run(context.Background(), "apt-get", "success"); err != nil || out != "done" {
		t.Fatalf("retry: %q %v", out, err)
	}
}
