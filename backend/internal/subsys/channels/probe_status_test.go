package channels

import (
	"context"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestProbeStatusRemainsReadableDuringProbe(t *testing.T) {
	s, _ := newTestSubsystem(t)
	cfg := channelConfig()
	ch := &cfg.Channels[1]
	ch.Probe = config.Probe{Enabled: true, FailThreshold: 1, RiseThreshold: 1}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	s.pausedUntil = time.Time{}
	previous := false
	for _, ok := range []bool{false, true, false} {
		if state := s.states[ch.ID]; state != nil {
			state.Next = time.Time{}
		}
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		s.Probe = func(context.Context, config.Channel, string) bool { close(entered); <-release; return ok }
		go func() { s.tick(context.Background(), cfg); close(finished) }()
		<-entered
		read := make(chan bool, 1)
		go func() { read <- s.ProbeDown(ch.ID) }()
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
		if s.ProbeDown(ch.ID) != previous {
			t.Fatal("completed result not published")
		}
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if s.ProbeDown(ch.ID) {
		t.Fatal("apply retained stale down status")
	}
	if s.ProbeDown("missing") {
		t.Fatal("missing channel reported down")
	}
}
