package multiwan

import (
	"context"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestProbeStatusRemainsReadableDuringProbe(t *testing.T) {
	c := New(&fakeRunner{}, t.TempDir(), nil)
	cfg := config.Default()
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "balance"
	cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0"}}
	cfg.WANs = []config.WAN{{ID: "wan", Index: 1, Interface: "if", Enabled: true, Probe: config.Probe{Enabled: true, FailThreshold: 1, RiseThreshold: 1}}}
	previous := false
	for _, ok := range []bool{false, true, false} {
		if state := c.states["wan"]; state != nil {
			state.Next = time.Time{}
		}
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		c.Probe = func(context.Context, config.WAN, string) bool { close(entered); <-release; return ok }
		go func() { c.tick(context.Background(), cfg); close(finished) }()
		<-entered
		read := make(chan bool, 1)
		go func() { read <- c.ProbeDown("wan") }()
		select {
		case down := <-read:
			if down != previous {
				close(release)
				<-finished
				t.Fatal("incomplete probe changed published status")
			}
		case <-time.After(time.Second):
			close(release)
			<-finished
			t.Fatal("status waits for network probe")
		}
		close(release)
		<-finished
		previous = !ok
		if c.ProbeDown("wan") != previous {
			t.Fatal("completed result not published")
		}
	}
	cfg.MultiWAN.Enabled = false
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if c.ProbeDown("wan") {
		t.Fatal("apply retained stale down status")
	}
	if c.ProbeDown("missing") {
		t.Fatal("missing uplink reported down")
	}
}
