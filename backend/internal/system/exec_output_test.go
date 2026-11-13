package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOutputHelperProcess(t *testing.T) {
	if os.Getenv("NETOS_OUTPUT_HELPER") != "1" {
		return
	}
	size, _ := strconv.Atoi(os.Getenv("NETOS_OUTPUT_SIZE"))
	var stream io.Writer = os.Stdout
	if os.Getenv("NETOS_OUTPUT_STDERR") == "1" {
		stream = os.Stderr
	}
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for size > 0 {
		n := min(size, len(chunk))
		if _, err := stream.Write(chunk[:n]); err != nil {
			os.Exit(9)
		}
		size -= n
	}
	if os.Getenv("NETOS_OUTPUT_SLEEP") == "1" {
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}

func TestExecOutputLimit(t *testing.T) {
	const limit = 64 << 10
	for _, stderr := range []bool{false, true} {
		for _, size := range []int{0, limit - 1, limit, limit + 1, 32 << 20} {
			t.Run(fmt.Sprintf("stderr=%v/size=%d", stderr, size), func(t *testing.T) {
				t.Setenv("NETOS_OUTPUT_HELPER", "1")
				t.Setenv("NETOS_OUTPUT_SIZE", strconv.Itoa(size))
				if stderr {
					t.Setenv("NETOS_OUTPUT_STDERR", "1")
				}
				if size > limit {
					// A completed write must not leave a sleeping child until timeout.
					t.Setenv("NETOS_OUTPUT_SLEEP", "1")
				}
				runner := &Exec{Timeout: 8 * time.Second, MaxOutputBytes: limit}
				for repeat := 0; repeat < 2; repeat++ {
					start := time.Now()
					out, err := runner.Run(context.Background(), os.Args[0], "-test.run=^TestOutputHelperProcess$")
					if (size > limit) != errors.Is(err, ErrOutputLimit) || (size <= limit && err != nil) {
						t.Fatalf("size=%d err=%v", size, err)
					}
					want := min(size, limit)
					if stderr {
						want = 0
					}
					if len(out) != want || out != strings.Repeat("x", want) {
						t.Fatalf("output length=%d want=%d", len(out), want)
					}
					if time.Since(start) > 3*time.Second {
						t.Fatal("command was not stopped promptly")
					}
				}
			})
		}
	}
}

func TestExecLimitedErrorsAndCancellation(t *testing.T) {
	runner := &Exec{MaxOutputBytes: 4096, Timeout: 50 * time.Millisecond}
	name, args := helperCommand(t, "fail-stderr")
	_, err := runner.Run(context.Background(), name, args...)
	if err == nil || errors.Is(err, ErrOutputLimit) || !strings.Contains(err.Error(), "deliberate stderr") {
		t.Fatalf("ordinary error changed: %v", err)
	}
	name, args = helperCommand(t, "sleep")
	start := time.Now()
	_, err = runner.Run(context.Background(), name, args...)
	if err == nil || errors.Is(err, ErrOutputLimit) || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Run(ctx, name, args...); err == nil || errors.Is(err, ErrOutputLimit) {
		t.Fatalf("cancellation: %v", err)
	}
}

// Includes the real process, pipe reads, buffering and returned string. The
// unlimited case uses the pre-limit path on the same generated input.
func BenchmarkExecOutput(b *testing.B) {
	for _, size := range []int{2 << 20, 32 << 20} {
		for _, limit := range []int{0, 4 << 20} {
			b.Run(fmt.Sprintf("size=%d/limit=%d", size, limit), func(b *testing.B) {
				b.Setenv("NETOS_OUTPUT_HELPER", "1")
				b.Setenv("NETOS_OUTPUT_SIZE", strconv.Itoa(size))
				runner := &Exec{MaxOutputBytes: limit}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out, err := runner.Run(context.Background(), os.Args[0], "-test.run=^TestOutputHelperProcess$")
					want := size
					if limit > 0 && size > limit {
						want = limit
						if !errors.Is(err, ErrOutputLimit) {
							b.Fatal(err)
						}
					} else if err != nil {
						b.Fatal(err)
					}
					if len(out) != want || strings.Count(out, "x") != want {
						b.Fatal("unexpected output")
					}
				}
			})
		}
	}
}
