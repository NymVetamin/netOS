package channels

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestProbeStatusDuringRealHTTP(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl required")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(200)
	}))
	defer server.Close()
	defer unblock()
	s := New(&system.Exec{}, t.TempDir())
	s.SysClassNet = t.TempDir()
	// Exercise the production curl probe over loopback without changing host routes.
	s.Probe = func(ctx context.Context, ch config.Channel, _ string) bool { return s.probe(ctx, ch, "lo") }
	cfg := config.Default()
	cfg.Channels = []config.Channel{{ID: "slow", Type: "xray", Index: 99, Enabled: true, Probe: config.Probe{Enabled: true, Type: "http", Timeout: 5, Targets: []string{server.URL}}}}
	finished := make(chan struct{})
	go func() { s.tick(context.Background(), cfg); close(finished) }()
	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("real HTTP probe not reached")
	}
	read := make(chan time.Duration, 1)
	go func() { start := time.Now(); s.ProbeDown("slow"); read <- time.Since(start) }()
	select {
	case elapsed := <-read:
		t.Logf("status during held real HTTP: %s", elapsed)
	case <-time.After(time.Second):
		t.Fatal("status blocked by HTTP")
	}
	unblock()
	<-finished
	if s.states["slow"].Successes != 1 || s.ProbeDown("slow") {
		t.Fatal("HTTP result lost")
	}
}
