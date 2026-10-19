package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type conflictProbe struct {
	calls int
	rows  []string
}

func (p *conflictProbe) IfupdownConflicts(context.Context, *config.Config) []string {
	p.calls++
	return append([]string(nil), p.rows...)
}
func TestNetworkConflictPollsShareObservation(t *testing.T) {
	p := &conflictProbe{rows: []string{"foreign"}}
	s := &Server{NetworkConflicts: p}
	cfg := config.Default()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); s.networkConflictsSnapshot(context.Background(), cfg) }()
	}
	wg.Wait()
	if p.calls != 1 {
		t.Fatalf("%d concurrent probes", p.calls)
	}
	rows := s.networkConflictsSnapshot(context.Background(), cfg)
	rows[0] = "changed"
	if s.networkConflictsSnapshot(context.Background(), cfg)[0] != "foreign" {
		t.Fatal("cache alias")
	}
	p.rows = nil
	cfg2 := config.Default()
	if len(s.networkConflictsSnapshot(context.Background(), cfg2)) != 0 || p.calls != 2 {
		t.Fatal("applied config did not invalidate")
	}
	s.networkConflictStatus.at = time.Now().Add(-2 * time.Second)
	p.rows = []string{"new"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.networkConflictsSnapshot(ctx, cfg2)
	if s.networkConflictsSnapshot(context.Background(), cfg2)[0] != "new" || p.calls != 4 {
		t.Fatal("expired/cancelled observation reused")
	}
	p.rows = nil
	s.networkConflictStatus.at = time.Now().Add(-2 * time.Second)
	if len(s.networkConflictsSnapshot(context.Background(), cfg2)) != 0 {
		t.Fatal("external conflict removal not observed")
	}
}
