//go:build linux

package xraylog

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestRunTerminationChild(t *testing.T) {
	marker := os.Getenv("NETOS_XRAYLOG_TERM_MARKER")
	if marker == "" {
		return
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(2)
	}
	for {
		select {
		case <-sigs:
			_ = os.WriteFile(marker+".stopped", []byte("stopped"), 0600)
			os.Exit(0)
		case <-time.After(10 * time.Millisecond):
			_, _ = io.WriteString(os.Stdout, "safe diagnostic\n")
		}
	}
}

func TestRunCancellationAndBrokenSinkReapChild(t *testing.T) {
	for _, broken := range []bool{false, true} {
		marker := filepath.Join(t.TempDir(), "pid")
		t.Setenv("NETOS_XRAYLOG_TERM_MARKER", marker)
		ctx, cancel := context.WithCancel(context.Background())
		var out io.Writer = io.Discard
		if broken {
			out = brokenWriter{}
		}
		done := make(chan error, 1)
		go func() { done <- Run(ctx, os.Args[0], []string{"-test.run=^TestRunTerminationChild$"}, out) }()
		deadline := time.Now().Add(5 * time.Second)
		var pid int
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(marker); err == nil {
				pid, _ = strconv.Atoi(string(data))
				if pid > 0 {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		if pid == 0 {
			cancel()
			t.Fatal("child did not start")
		}
		if !broken {
			cancel()
		}
		select {
		case err := <-done:
			if broken && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			if !broken && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(7 * time.Second):
			cancel()
			t.Fatal("child not reaped")
		}
		cancel()
		if _, err := os.Stat(marker + ".stopped"); err != nil {
			t.Fatal("SIGTERM not handled", err)
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatal("child still present", err)
		}
	}
}
