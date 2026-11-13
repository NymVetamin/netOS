package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
)

type handshakeMonitorRunner struct {
	started, release chan struct{}
	once             sync.Once
	calls            atomic.Int32
}

func (r *handshakeMonitorRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls.Add(1)
	r.once.Do(func() { close(r.started); <-r.release })
	if len(args) != 3 || name != "wg" {
		return "", fmt.Errorf("unexpected telemetry")
	}
	switch args[2] {
	case "latest-handshakes":
		return "public0 100\n", nil
	case "endpoints":
		return "public0 192.0.2.1:51820\n", nil
	case "transfer":
		return "public0 1 2\n", nil
	}
	return "", fmt.Errorf("unexpected field")
}
func (r *handshakeMonitorRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestHandshakeMonitorUsesExistingPollAndRejectsLateCycle(t *testing.T) {
	for _, scenario := range []string{"normal", "cancelled", "config-changed"} {
		t.Run(scenario, func(t *testing.T) {
			engine := apply.NewEngine(nil, true)
			if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
				t.Fatal(err)
			}
			server := handshakeSamples(1)[0].server
			engine.Current().VPNServers = []config.VPNServer{server}
			run := &handshakeMonitorRunner{started: make(chan struct{}), release: make(chan struct{})}
			logger := &lifecycleLogger{}
			s := &Server{Engine: engine, Logger: logger, Collector: &runtime.Collector{Runner: run}}
			// The cycle must finish its normal stale-cache cleanup before we
			// cancel; otherwise cancellation alone could mask a stale-config bug.
			s.vpnStatus = map[string]*vpnStatusCache{"removed-server": {}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { s.monitorVPNClients(ctx); close(done) }()
			select {
			case <-run.started:
			case <-time.After(time.Second):
				t.Fatal("monitor did not start")
			}
			if scenario == "cancelled" {
				cancel()
			}
			if scenario == "config-changed" {
				if _, err := engine.Apply(context.Background(), config.Default(), 2, false); err != nil {
					t.Fatal(err)
				}
			}
			close(run.release)
			if scenario != "cancelled" {
				deadline := time.Now().Add(2 * time.Second)
				ready := false
				for time.Now().Before(deadline) {
					s.vpnStatusMu.Lock()
					cache := s.vpnStatus[server.ID]
					_, staleCache := s.vpnStatus["removed-server"]
					s.vpnStatusMu.Unlock()
					if cache != nil {
						cache.mu.Lock()
						ready = cache.refreshing == nil && !cache.at.IsZero() && !staleCache
						cache.mu.Unlock()
					}
					if ready {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if !ready {
					t.Fatal("snapshot did not complete")
				}
				if scenario == "normal" {
					for time.Now().Before(deadline) && logger.String() == "" {
						time.Sleep(time.Millisecond)
					}
					if logger.String() == "" {
						t.Fatal("monitor did not emit observation")
					}
					for i := 0; i < 32; i++ {
						s.vpnClients(context.Background(), server)
					}
					if strings.Count(logger.String(), vpnHandshakeMarker) != 1 {
						t.Fatal("browser reads duplicated event")
					}
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("monitor did not stop")
			}
			if scenario != "normal" && logger.String() != "" {
				t.Fatal("late cycle emitted", logger.String())
			}
			if scenario == "normal" && run.calls.Load() != 3 {
				t.Fatal("additional polling", run.calls.Load())
			}
		})
	}
}
