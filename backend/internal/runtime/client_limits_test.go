package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryLimitDoesNotLeakOutsidePeriod(t *testing.T) {
	h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	h.enabled = true
	now := time.Now().UTC()
	lost := now.Add(-2 * time.Hour)
	for i := 0; i < 4097; i++ {
		h.AddDNS(lost, "192.0.2.2", fmt.Sprintf("d%d.example", i))
	}
	r, e := h.Report(context.Background(), now.Add(-3*time.Minute), now, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	if r.Limited {
		t.Fatal("old DNS loss reported as a limit in the current three-minute window")
	}
	r, e = h.Report(context.Background(), lost.Add(-time.Minute), lost.Add(time.Minute), nil, false)
	if e != nil || !r.Limited {
		t.Fatal("actual loss hidden", r, e)
	}
}

func TestHistoryLimitPersistenceRetryAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	h, e := NewClientHistory(path, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { h.Close() }()
	now := time.Now().UTC().Truncate(time.Second)
	h.noteLimitLocked("dns-buffer", now.Unix()-1, now.Unix())
	if _, e = h.db.Exec("CREATE TRIGGER reject_limit BEFORE INSERT ON history_limits BEGIN SELECT RAISE(ABORT,'test loss metadata failure'); END"); e != nil {
		t.Fatal(e)
	}
	if e = h.persist(now, nil); e == nil {
		t.Fatal("failed metadata commit accepted")
	}
	if len(h.pendingLimits) == 0 {
		t.Fatal("failed commit discarded pending loss")
	}
	if _, e = h.db.Exec("DROP TRIGGER reject_limit"); e != nil {
		t.Fatal(e)
	}
	if e = h.persist(now, nil); e != nil {
		t.Fatal(e)
	}
	if e = h.persist(now, nil); e != nil {
		t.Fatal(e)
	}
	if len(h.pendingLimits) != 0 {
		t.Fatal("successful commit retained pending loss")
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	h, e = NewClientHistory(path, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := h.Report(context.Background(), now.Add(-time.Minute), now.Add(time.Minute), nil, false)
	if e != nil || !r.Limited || len(r.Limits) != 1 || r.Limits[0].Kind != "dns-buffer" {
		t.Fatal("loss did not survive reopen", r, e)
	}
	if e = h.prune(now.Add(8 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = h.db.QueryRow("SELECT COUNT(*) FROM history_limits").Scan(&count); e != nil || count != 0 || len(h.limits) != 0 {
		t.Fatal("expired losses retained", count, e)
	}
}

func TestHistoryQuotaLossIsAtomicAndExact(t *testing.T) {
	h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if _, e = h.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<50002)
 INSERT INTO domains SELECT ?-i,'a','example.test',1,?-i,?-i FROM n`, now.Unix(), now.Unix(), now.Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = h.db.Exec("CREATE TRIGGER reject_limit BEFORE INSERT ON history_limits BEGIN SELECT RAISE(ABORT,'test loss metadata failure'); END"); e != nil {
		t.Fatal(e)
	}
	if e = h.prune(now); e == nil {
		t.Fatal("quota committed without loss metadata")
	}
	var count int
	if e = h.db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 50003 || len(h.limits) != 0 {
		t.Fatal("rollback left partial quota result", count, h.limits)
	}
	if _, e = h.db.Exec("DROP TRIGGER reject_limit"); e != nil {
		t.Fatal(e)
	}
	if e = h.prune(now); e != nil {
		t.Fatal(e)
	}
	r, e := h.Report(context.Background(), now.Add(-24*time.Hour), now, nil, false)
	if e != nil || len(r.Limits) != 1 || r.Limits[0].Kind != "domains" || r.Limits[0].From != now.Unix()-50002 || r.Limits[0].To != now.Unix()-50000 {
		t.Fatal("incorrect deleted range", r, e)
	}
	r, e = h.Report(context.Background(), now.Add(-time.Hour), now, nil, false)
	if e != nil || r.Limited {
		t.Fatal("old quota affects current range", r, e)
	}
}

func TestHistoryAvailableIncludesCompactAndLegacy(t *testing.T) {
	h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	now := time.Now().UTC().Truncate(time.Second)
	v := ClientCounter{ID: "a", Name: "a", Address: "192.0.2.2"}
	if e = h.persist(now, []ClientCounter{v}); e != nil {
		t.Fatal(e)
	}
	if e = h.persist(now.Add(30*time.Second), []ClientCounter{v}); e != nil {
		t.Fatal(e)
	}
	v.RX = 100
	if e = h.persist(now.Add(time.Minute), []ClientCounter{v}); e != nil {
		t.Fatal(e)
	}
	r, e := h.Report(context.Background(), now.Add(2*time.Minute), now.Add(3*time.Minute), nil, false)
	if e != nil || len(r.Clients) != 0 || r.Available == nil || r.Available.From != now.Unix()+30 || r.Available.To != now.Unix()+60 {
		t.Fatal("availability lost on empty selection", r, e)
	}
}

func BenchmarkHistoryLimitReport(b *testing.B) {
	for _, days := range []int{1, 7} {
		b.Run(fmt.Sprint(days), func(b *testing.B) {
			h, e := NewClientHistory(filepath.Join(b.TempDir(), "history.db"), nil, nil, nil)
			if e != nil {
				b.Fatal(e)
			}
			defer h.Close()
			now := time.Now().UTC()
			for _, kind := range []string{"traffic", "traffic-idle", "domains", "resources", "dns-buffer", "resource-buffer", "journal"} {
				h.noteLimitLocked(kind, now.Add(-time.Duration(days)*24*time.Hour).Unix(), now.Unix())
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e = h.Report(context.Background(), now.Add(-3*time.Minute), now, nil, false); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

func BenchmarkHistoryLimitPrune(b *testing.B) {
	for _, dropped := range []int{100, 50000} {
		b.Run(fmt.Sprint(dropped), func(b *testing.B) {
			h, err := NewClientHistory(filepath.Join(b.TempDir(), "history.db"), nil, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer h.Close()
			now := time.Now().UTC().Truncate(time.Second)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if _, err = h.db.Exec("DELETE FROM domains"); err != nil {
					b.Fatal(err)
				}
				if _, err = h.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<?)
 INSERT INTO domains SELECT ?-i,'a','example.test',1,?-i,?-i FROM n`, 49999+dropped, now.Unix(), now.Unix(), now.Unix()); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err = h.prune(now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
