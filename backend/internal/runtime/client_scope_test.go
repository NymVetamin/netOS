package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type scopeCountersRunner struct {
	fail  bool
	bytes int
	calls int
}

func (r *scopeCountersRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls++
	if name == "ip" {
		return "[]", nil
	}
	if r.fail {
		return "", errors.New("counter read failed")
	}
	return fmt.Sprintf(`{"nftables":[{"set":{"name":"up4","elem":[{"elem":{"val":"192.0.2.2","counter":{"bytes":%d}}},{"elem":{"val":"203.0.113.9","counter":{"bytes":%d}}}]}}]}`, r.bytes, r.bytes), nil
}
func (r *scopeCountersRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	panic("unexpected mutation")
}

func TestClientSampleRejectsStaleExitCounters(t *testing.T) {
	c := &config.Config{Interfaces: []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}}, Networks: []config.Network{{Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}}
	c.TrafficMonitor.Enabled = true
	r := &scopeCountersRunner{bytes: 100}
	dir := t.TempDir()
	h, e := NewClientHistory(filepath.Join(dir, "history.db"), r, NewCollector(r, filepath.Join(dir, "absent-leases")), func() *config.Config { return c })
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	h.dnsCancel = func() {} // This test exercises sampling, not the journal watcher.
	h.sample(context.Background())
	if len(h.baseline) != 1 {
		t.Fatalf("stale exit counter accepted: %+v", h.baseline)
	}
	for k, v := range h.baseline {
		v.At = v.At.Add(-30 * time.Second)
		h.baseline[k] = v
	}
	h.lastPersist = time.Time{}
	r.bytes = 200
	h.sample(context.Background())
	report, e := h.Report(context.Background(), time.Now().Add(-time.Minute), time.Now().Add(time.Second), nil, false)
	if e != nil || len(report.Clients) != 1 || report.Clients[0].Address != "192.0.2.2" || report.Clients[0].TX != 100 {
		t.Fatalf("wrong accounting: %+v %v", report, e)
	}
	r.fail = true
	h.sample(context.Background())
	if h.problem == "" {
		t.Fatal("counter error hidden")
	}
	r.fail = false
	c.Networks[0].RouterAddress = "203.0.113.1/24"
	h.lastPersist = time.Time{}
	h.sample(context.Background())
	if h.problem != "" || len(h.baseline) != 1 {
		t.Fatal("recovery failed", h.problem, h.baseline)
	}
	for _, v := range h.baseline {
		if v.Address != "203.0.113.9" {
			t.Fatal("old scope retained", v)
		}
	}
	if r.calls != 8 {
		t.Fatal("unexpected commands", r.calls)
	}
}

func TestClientHistoryRetryCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := &config.Config{
			Interfaces: []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}},
			Networks:   []config.Network{{Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}},
		}
		cfg.TrafficMonitor.Enabled = true
		r := &scopeCountersRunner{bytes: 100}
		dir := t.TempDir()
		h, err := NewClientHistory(filepath.Join(dir, "history.db"), r, NewCollector(r, filepath.Join(dir, "leases")), func() *config.Config { return cfg })
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		h.dnsCancel = func() {}
		ctx, stop := context.WithCancel(context.Background())
		defer func() { stop(); synctest.Wait() }()
		go h.Run(ctx)
		synctest.Wait()
		start := h.lastPersist
		r.fail = true
		time.Sleep(2*HistoryInterval - time.Second)
		synctest.Wait()
		if r.calls != 4 || h.problem == "" || !h.lastPersist.Equal(start) {
			t.Errorf("idle outage: commands=%d, problem=%q, last write=%v", r.calls, h.problem, h.lastPersist)
		}
		r.fail = false
		r.bytes = 250
		time.Sleep(time.Second)
		synctest.Wait()
		if h.problem != "" || !h.lastPersist.Equal(start.Add(2*HistoryInterval)) {
			t.Fatalf("did not recover on next interval: %q, %v", h.problem, h.lastPersist)
		}
		var delta int
		if err := h.db.QueryRow("SELECT tx FROM traffic WHERE address='192.0.2.2'").Scan(&delta); err != nil || delta != 150 {
			t.Fatalf("recovered traffic=%d err=%v", delta, err)
		}
		r.fail = true
		before := r.calls
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if r.calls-before != 40 {
			t.Errorf("ten-minute outage: %d commands, want 40", r.calls-before)
		}
	})
}

func TestClientHistoryReplaysFailedWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := &config.Config{
			Interfaces: []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}},
			Networks:   []config.Network{{Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}},
		}
		cfg.TrafficMonitor.Enabled = true
		dir := t.TempDir()
		r := &scopeCountersRunner{bytes: 100}
		h, err := NewClientHistory(filepath.Join(dir, "history.db"), r, NewCollector(r, filepath.Join(dir, "leases")), func() *config.Config { return cfg })
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		h.dnsCancel = func() {}
		ctx := context.Background()
		start := time.Now()
		h.sample(ctx)
		if _, err := h.db.Exec("CREATE TRIGGER reject_traffic BEFORE INSERT ON traffic BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
			t.Fatal(err)
		}
		h.AddDNS(start, "192.0.2.2", "example.test")
		for i := 1; i <= 2; i++ {
			time.Sleep(31 * time.Second)
			r.bytes += 70
			h.sample(ctx)
			if i == 1 && h.problem == "" {
				t.Fatal("write failure hidden")
			}
			if i == 1 {
				if _, err := h.db.Exec("DROP TRIGGER reject_traffic"); err != nil {
					t.Fatal(err)
				}
			} else if h.problem != "" {
				t.Fatal(h.problem)
			}
		}
		rows, err := h.db.Query("SELECT at,tx,seconds FROM traffic ORDER BY at")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			var at, tx int64
			var seconds float64
			if err := rows.Scan(&at, &tx, &seconds); err != nil {
				t.Fatal(err)
			}
			if at != start.Unix()+int64(count*31) || tx != 70 || seconds != 31 {
				t.Fatalf("sample %d: %d %d %v", count, at, tx, seconds)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("saved %d of 2 measurements", count)
		}
		rows.Close()
		var at, n int64
		if err := h.db.QueryRow("SELECT at,SUM(n) FROM domains").Scan(&at, &n); err != nil || at != start.Unix() || n != 1 {
			t.Fatalf("DNS saved at %d, count %d: %v", at, n, err)
		}
	})
}

func TestClientHistoryRetryAfterPartialRecovery(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	start := time.Unix(1800000000, 0)
	save := func(i int) error {
		return h.persistObservations(start.Add(time.Duration(i)*31*time.Second), []ClientCounter{{ID: "a", Address: "192.0.2.1", RX: uint64(i * 10)}})
	}
	exec := func(q string) {
		t.Helper()
		if _, err := h.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := save(0); err != nil {
		t.Fatal(err)
	}
	exec("CREATE TRIGGER reject BEFORE INSERT ON traffic BEGIN SELECT RAISE(ABORT,'unavailable'); END")
	for i := 1; i <= 2; i++ {
		if err := save(i); err == nil {
			t.Fatal("missing storage failure")
		}
	}
	exec("DROP TRIGGER reject")
	exec(fmt.Sprintf("CREATE TRIGGER reject BEFORE INSERT ON traffic WHEN NEW.at=%d BEGIN SELECT RAISE(ABORT,'partial recovery'); END", start.Unix()+62))
	if err := save(3); err == nil {
		t.Fatal("missing partial failure")
	}
	exec("DROP TRIGGER reject")
	if err := save(4); err != nil {
		t.Fatal(err)
	}
	var n, bytes, seconds int
	if err := h.db.QueryRow("SELECT COUNT(*),SUM(rx),SUM(seconds) FROM traffic").Scan(&n, &bytes, &seconds); err != nil || n != 4 || bytes != 40 || seconds != 124 || len(h.pendingTraffic) != 0 {
		t.Fatalf("rows=%d bytes=%d seconds=%d: %v", n, bytes, seconds, err)
	}
	if err := save(8); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow("SELECT COUNT(*) FROM traffic").Scan(&n); err != nil || n != 4 {
		t.Fatalf("counted an unobserved gap: %d %v", n, err)
	}
}

func TestClientHistoryRetryBufferLimit(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	now := time.Unix(1800000000, 0)
	clients := make([]ClientCounter, maxCachedTrafficRows)
	if err := h.persistObservations(now, clients); err == nil {
		t.Fatal("missing database error")
	}
	if err := h.persistObservations(now.Add(HistoryInterval), nil); err == nil {
		t.Fatal("missing database error")
	}
	limits := h.reportLimits(now.Unix(), now.Unix())
	if h.pendingTrafficSize != 1 || len(h.pendingTraffic) != 1 || len(limits) != 1 || limits[0].From != now.Unix() {
		t.Fatalf("pending=%d limits=%v", h.pendingTrafficSize, limits)
	}
	later := now.Add(8 * 24 * time.Hour)
	if err := h.persistObservations(later, nil); err == nil {
		t.Fatal("missing database error")
	}
	if len(h.pendingTraffic) != 1 || !h.pendingTraffic[0].at.Equal(later) {
		t.Fatal("expired observation retained")
	}
}
