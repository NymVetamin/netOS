package runtime

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func compareHistoryTraffic(t *testing.T, h *ClientHistory, from, to time.Time, selected []string) {
	t.Helper()
	got, gs, ge := h.reportTraffic(context.Background(), from, to, selected, true)
	want, ws, we := h.reportTrafficSQL(context.Background(), from, to, selected, true)
	if (ge != nil) != (we != nil) {
		t.Fatalf("error mismatch: cache=%v SQL=%v", ge, we)
	}
	if ge != nil {
		return
	}
	if !reflect.DeepEqual(got.Clients, want.Clients) || !reflect.DeepEqual(gs, ws) {
		t.Fatalf("totals/selection mismatch:\n%+v %v\n%+v %v", got.Clients, gs, want.Clients, ws)
	}
	less := func(points []ClientPoint) {
		sort.Slice(points, func(i, j int) bool {
			if points[i].At == points[j].At {
				return points[i].ID < points[j].ID
			}
			return points[i].At < points[j].At
		})
	}
	less(want.Points)
	less(got.Points)
	if len(got.Points) != len(want.Points) {
		t.Fatalf("point count %d != %d", len(got.Points), len(want.Points))
	}
	for i, p := range got.Points {
		w := want.Points[i]
		close := func(a, b float64) bool { return math.Abs(a-b) <= 1e-10*math.Max(1, math.Abs(b)) }
		if p.At != w.At || p.ID != w.ID || !close(p.RX, w.RX) || !close(p.TX, w.TX) {
			t.Fatalf("point %d mismatch: %+v != %+v", i, p, w)
		}
	}
}

func TestTrafficCacheMatchesSQLWindowsAndSelection(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Unix(1800000000, 0)
	tx, _ := h.db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)")
	for i := 0; i < 1500; i++ {
		for c := 0; c < 7; c++ {
			// Reverse timestamps, rename/address changes, irregular intervals,
			// idle samples and missing intervals must retain their old meaning.
			if i%11 == c {
				continue
			}
			at := now.Add(-time.Duration(i*31) * time.Second).Unix()
			rx, sent := i*c%101, i*(c+1)%79
			if c == 6 {
				rx, sent = 0, 0
			}
			if _, err := stmt.Exec(at, fmt.Sprint(c), fmt.Sprintf("name-%d-%d", c, i/100), fmt.Sprintf("192.0.2.%d", i/100+1), rx, sent, 29.125+float64(i%3)); err != nil {
				t.Fatal(err)
			}
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int{1, 300, 3600, 7200, 86400, 604800} {
		for _, offset := range []int{0, 1, 31, 1512} {
			end := now.Add(-time.Duration(offset) * time.Second)
			for _, ids := range [][]string{nil, {"0"}, {"6"}, {"0", "0", "2", "missing"}} {
				compareHistoryTraffic(t, h, end.Add(-time.Duration(seconds)*time.Second), end, ids)
			}
		}
	}
	compareHistoryTraffic(t, h, now.Add(time.Second), now.Add(time.Hour), nil)
	compareHistoryTraffic(t, h, now.Add(-time.Hour), now, make([]string, 17))
}

func TestTrafficCacheCommittedWritesPruneAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	h, err := NewClientHistory(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { h.Close() }()
	now := time.Unix(1800000000, 0)
	v := ClientCounter{ID: "a", Name: "first", Address: "192.0.2.1"}
	if err := h.persist(now, []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil) // initialize empty cache
	v.RX, v.TX = 100, 300
	if err := h.persist(now.Add(30*time.Second), []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	v.Name, v.Address, v.RX = "renamed", "192.0.2.2", 900 // new baseline only
	if err := h.persist(now.Add(time.Minute), []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	v.RX += 100
	if err := h.persist(now.Add(90*time.Second), []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	compareHistoryTraffic(t, h, now, now.Add(30*time.Second), nil) // latest name, old bytes
	if _, err := h.db.Exec("CREATE TRIGGER reject_traffic BEFORE INSERT ON traffic BEGIN SELECT RAISE(ABORT, 'write failed'); END"); err != nil {
		t.Fatal(err)
	}
	v.RX += 500
	if err := h.persist(now.Add(120*time.Second), []ClientCounter{v}); err == nil {
		t.Fatal("expected write failure")
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	h.db.Exec("DROP TRIGGER reject_traffic")
	if err := h.persist(now.Add(120*time.Second), []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	if err := h.prune(now.Add(7*24*time.Hour + time.Minute)); err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	h.Close()
	h, err = NewClientHistory(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := h.reportTraffic(ctx, now, now.Add(time.Hour), nil, true); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	// Oversized histories use the original SQL path until pruning permits a cache.
	h.trafficCache, h.trafficCacheBlocked = nil, true
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
}

func TestTrafficCacheConcurrentReaderAndWriter(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Unix(1800000000, 0)
	v := ClientCounter{ID: "a", Name: "client", Address: "192.0.2.1"}
	if err := h.persist(now, []ClientCounter{v}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				if _, err := h.Report(context.Background(), now, now.Add(time.Hour), nil, true); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := 1; i <= 40; i++ {
		v.RX += 100
		if err := h.persist(now.Add(time.Duration(i)*30*time.Second), []ClientCounter{v}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	compareHistoryTraffic(t, h, now, now.Add(time.Hour), nil)
	r, _, err := h.reportTraffic(context.Background(), now, now.Add(time.Hour), nil, true)
	if err != nil || len(r.Clients) != 1 || r.Clients[0].RX != 4000 {
		t.Fatalf("lost/doubled samples: %+v %v", r.Clients, err)
	}
}

func TestTrafficCacheLimitFallsBackAndRecoversAfterPrune(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	_, err = h.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
INSERT INTO traffic SELECT CASE WHEN i<3 THEN 1000 ELSE 2000 END,printf('id%05d',i),'name','192.0.2.1',i,i,30 FROM n`, maxCachedTrafficClients+1)
	if err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, time.Unix(0, 0), time.Unix(3000, 0), nil)
	if h.trafficCache != nil || !h.trafficCacheBlocked {
		t.Fatal("oversized identity cache not bounded")
	}
	if err := h.prune(time.Unix(1500, 0).Add(7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	compareHistoryTraffic(t, h, time.Unix(0, 0), time.Unix(3000, 0), nil)
	if h.trafficCache == nil || h.trafficCacheBlocked {
		t.Fatal("bounded cache did not recover")
	}
}

func BenchmarkTrafficReport(b *testing.B) {
	h, err := NewClientHistory(filepath.Join(b.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer h.Close()
	now := time.Unix(1800000000, 0)
	tx, _ := h.db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)")
	for i := 0; i < 8440; i++ {
		for c := 0; c < 3; c++ {
			id := fmt.Sprintf("client%d", c)
			if _, err := stmt.Exec(now.Unix()-int64(i*30), id, id, "192.0.2.1", i%100, i%73, 30); err != nil {
				b.Fatal(err)
			}
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	for _, variant := range []string{"sql", "sql-summary", "cached", "cached-summary", "cold"} {
		b.Run(variant, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var err error
				if variant == "sql" || variant == "sql-summary" {
					_, _, err = h.reportTrafficSQL(context.Background(), now.Add(-7*24*time.Hour), now, nil, variant != "sql-summary")
				} else {
					if variant == "cold" {
						h.trafficCache = nil
					}
					_, _, err = h.reportTraffic(context.Background(), now.Add(-7*24*time.Hour), now, nil, variant != "cached-summary")
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
