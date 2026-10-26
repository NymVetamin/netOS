package api

import (
	"context"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
)

type snapshotPoll struct{ reply chan string }
type snapshotRunner struct{ calls chan snapshotPoll }

func (r *snapshotRunner) Run(ctx context.Context, _ string, _ ...string) (string, error) {
	p := snapshotPoll{reply: make(chan string, 1)}
	select {
	case r.calls <- p:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case value := <-p.reply:
		return value, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func (r *snapshotRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestVPNWarmSnapshotAvailableDuringRefresh(t *testing.T) {
	r := &snapshotRunner{calls: make(chan snapshotPoll, 4)}
	s := &Server{Collector: &rt.Collector{Runner: r}}
	v := config.VPNServer{ID: "oc", Type: "ocserv", Enabled: true, Peers: []config.VPNPeer{{ID: "phone", Enabled: true}}}
	done := make(chan []vpnClientStatus, 1)
	go func() { done <- s.vpnClients(context.Background(), v) }()
	(<-r.calls).reply <- "[]"
	<-done
	// Windows clocks may give consecutive calls the same timestamp.
	cache := s.vpnStatus[v.ID]
	cache.mu.Lock()
	cache.at = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	go func() { rows, _ := s.vpnClientSnapshot(context.Background(), v, time.Now()); done <- rows }()
	refresh := <-r.calls
	warm := make(chan []vpnClientStatus, 1)
	go func() { warm <- s.vpnClients(context.Background(), v) }()
	select {
	case rows := <-warm:
		if len(rows) != 1 || rows[0].State != "offline" {
			t.Fatal(rows)
		}
		rows[0].State = "caller mutation"
	case <-time.After(time.Second):
		refresh.reply <- "[]"
		<-done
		t.Fatal("warm reader blocked on external refresh")
	}
	refresh.reply <- "[]"
	if rows := <-done; rows[0].State != "offline" {
		t.Fatal("returned slice changed snapshot", rows)
	}
}

func TestVPNColdCancellationAndConfigurationIsolation(t *testing.T) {
	r := &snapshotRunner{calls: make(chan snapshotPoll, 4)}
	s := &Server{Collector: &rt.Collector{Runner: r}}
	v := config.VPNServer{ID: "oc", Type: "ocserv", Enabled: true, Peers: []config.VPNPeer{{ID: "old", Enabled: true}}}
	oldCtx, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	oldDone := make(chan struct{})
	go func() { s.vpnClients(oldCtx, v); close(oldDone) }()
	<-r.calls
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWait()
	if rows, at := s.vpnClientSnapshot(waitCtx, v, time.Time{}); len(rows) != 0 || !at.IsZero() {
		t.Fatal("cancelled waiter returned a fabricated snapshot")
	}
	if len(r.calls) != 0 {
		t.Fatal("cold waiter duplicated the poll")
	}
	changed := v
	changed.Peers = []config.VPNPeer{{ID: "new", Enabled: true}}
	newDone := make(chan []vpnClientStatus, 1)
	go func() { newDone <- s.vpnClients(context.Background(), changed) }()
	(<-r.calls).reply <- "[]"
	if rows := <-newDone; len(rows) != 1 || rows[0].ID != "new" {
		t.Fatal("new config inherited old peers", rows)
	}
	cancelOld()
	<-oldDone
	if rows := s.vpnClients(context.Background(), changed); len(rows) != 1 || rows[0].ID != "new" {
		t.Fatal("old cancellation overwrote new config", rows)
	}
	if len(r.calls) != 0 {
		t.Fatal("warm retry unnecessarily polled")
	}
}

func TestVPNCancelledPollCanBeRetried(t *testing.T) {
	r := &snapshotRunner{calls: make(chan snapshotPoll, 4)}
	s := &Server{Collector: &rt.Collector{Runner: r}}
	v := config.VPNServer{ID: "oc", Type: "ocserv", Enabled: true, Peers: []config.VPNPeer{{ID: "phone", Enabled: true}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan time.Time, 1)
	go func() { _, at := s.vpnClientSnapshot(ctx, v, time.Time{}); done <- at }()
	<-r.calls
	cancel()
	if at := <-done; !at.IsZero() {
		t.Fatal("cancelled poll published a snapshot")
	}
	go func() { _, at := s.vpnClientSnapshot(context.Background(), v, time.Time{}); done <- at }()
	(<-r.calls).reply <- "[]"
	if at := <-done; at.IsZero() {
		t.Fatal("retry did not publish")
	}
	if rows := s.vpnClients(context.Background(), v); len(rows) != 1 || rows[0].State != "offline" || len(r.calls) != 0 {
		t.Fatal("retry was not cached", rows)
	}
}
