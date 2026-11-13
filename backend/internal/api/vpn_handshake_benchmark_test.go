package api

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/runtime"
)

type handshakeBenchRunner struct {
	fields         [2]map[string]string
	version, calls int
}

func (r *handshakeBenchRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.calls++
	return r.fields[r.version][args[2]], nil
}
func (r *handshakeBenchRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type handshakeBenchLogger struct{ writes int }

func (l *handshakeBenchLogger) Infof(format string, args ...any) {
	l.writes++
	fmt.Fprintf(io.Discard, format, args...)
}
func (l *handshakeBenchLogger) Warnf(string, ...any)  {}
func (l *handshakeBenchLogger) Errorf(string, ...any) {}

// Baseline is the same snapshot call used before observations were added.
// OS commands return identical prepared public telemetry in all modes: this
// measures the Go caller chain, not kernel/command CPU or journal disk writes.
func BenchmarkHandshakeSnapshotChain(b *testing.B) {
	for _, n := range []int{30, 3000} {
		for _, mode := range []string{"baseline", "unchanged", "changed"} {
			b.Run(fmt.Sprintf("%d/%s", n, mode), func(b *testing.B) {
				samples := handshakeSamples(n)
				run := &handshakeBenchRunner{}
				for version := range run.fields {
					var hs, ep, tr strings.Builder
					for i := 0; i < n; i++ {
						fmt.Fprintf(&hs, "public%d %d\n", i, 100+version)
						fmt.Fprintf(&ep, "public%d 192.0.2.1:51820\n", i)
						fmt.Fprintf(&tr, "public%d 1 2\n", i)
					}
					run.fields[version] = map[string]string{"latest-handshakes": hs.String(), "endpoints": ep.String(), "transfer": tr.String()}
				}
				logger := &handshakeBenchLogger{}
				s := &Server{Collector: &runtime.Collector{Runner: run}, Logger: logger}
				var observer vpnHandshakeObserver
				var at time.Time
				samples[0].rows, at = s.vpnClientSnapshot(context.Background(), samples[0].server, time.Now())
				observer.observe(samples, time.Now())
				run.calls = 0
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if mode == "changed" {
						run.version = (i + 1) % 2
					}
					samples[0].rows, at = s.vpnClientSnapshot(context.Background(), samples[0].server, at.Add(time.Nanosecond))
					if mode != "baseline" {
						s.logVPNHandshakes(observer.observe(samples, time.Now()))
					}
				}
				b.StopTimer()
				if run.calls != 3*b.N {
					b.Fatal("changed command count", run.calls)
				}
				if mode == "unchanged" && logger.writes != 0 {
					b.Fatal("idle event writes", logger.writes)
				}
				if mode == "changed" && logger.writes != min(n, 65)*b.N {
					b.Fatal("wrong bounded write count", logger.writes)
				}
			})
		}
	}
}
