package multiwan

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
	c := New(&system.Exec{}, t.TempDir(), nil)
	cfg := config.Default()
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "balance"
	cfg.Interfaces = []config.Interface{{ID: "loop", Name: "lo"}}
	cfg.WANs = []config.WAN{{ID: "slow", Interface: "loop", Enabled: true, Probe: config.Probe{Enabled: true, Type: "http", Timeout: 5, Targets: []string{server.URL}}}}
	finished := make(chan struct{})
	go func() { c.tick(context.Background(), cfg); close(finished) }()
	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("real HTTP probe not reached")
	}
	read := make(chan time.Duration, 1)
	go func() { start := time.Now(); c.ProbeDown("slow"); read <- time.Since(start) }()
	select {
	case elapsed := <-read:
		t.Logf("status during held real HTTP: %s", elapsed)
	case <-time.After(time.Second):
		t.Fatal("status blocked by HTTP")
	}
	unblock()
	<-finished
	if c.states["slow"].Successes != 1 || c.ProbeDown("slow") {
		t.Fatal("HTTP result lost")
	}
}
