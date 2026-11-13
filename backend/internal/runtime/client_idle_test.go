package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"testing"
	"time"
)

func TestIdleHistoryKeepsExactWindowsWithoutRowsPerPoll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	h, e := NewClientHistory(path, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { h.Close() }()
	ref, e := NewClientHistory(filepath.Join(t.TempDir(), "reference.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer ref.Close()
	start := time.Unix(1800000000, 0)
	now := start
	values := []ClientCounter{{ID: "a", Name: "first", Address: "192.0.2.2"}, {ID: "b", Name: "idle", Address: "192.0.2.3"}}
	if e = h.persist(now, values); e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 240; i++ {
		seconds := 30 + i%2
		now = now.Add(time.Duration(seconds) * time.Second)
		delta := uint64(0)
		if i%37 == 0 {
			delta = 100
			values[0].RX += delta
		}
		if i == 180 {
			values[0].Name = "renamed"
			values[1].Name = "idle-renamed"
		}
		if e = h.persist(now, values); e != nil {
			t.Fatal(e)
		}
		for j, v := range values {
			rx := uint64(0)
			if j == 0 {
				rx = delta
			}
			if _, e = ref.db.Exec("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)", now.Unix(), v.ID, v.Name, v.Address, rx, 0, seconds); e != nil {
				t.Fatal(e)
			}
		}
	}
	check := func() {
		t.Helper()
		for _, sql := range []bool{false, true} {
			h.trafficCache = nil
			h.trafficCacheBlocked = sql
			for _, window := range [][2]time.Time{{start, now}, {start.Add(91 * time.Second), start.Add(730 * time.Second)}, {now.Add(-77 * time.Second), now}, {now.Add(time.Second), now.Add(time.Minute)}} {
				for _, points := range []bool{false, true} {
					got, e := h.Report(context.Background(), window[0], window[1], nil, false, ClientReportOptions{OmitPoints: !points})
					if e != nil {
						t.Fatal(e)
					}
					want, e := ref.Report(context.Background(), window[0], window[1], nil, false, ClientReportOptions{OmitPoints: !points})
					if e != nil {
						t.Fatal(e)
					}
					// Compare public responses; implementation metadata is not an API field.
					for _, points := range [][]ClientPoint{got.Points, want.Points} {
						sort.Slice(points, func(i, j int) bool {
							if points[i].At == points[j].At {
								return points[i].ID < points[j].ID
							}
							return points[i].At < points[j].At
						})
					}
					if len(got.Clients) != len(want.Clients) || len(got.Points) != len(want.Points) {
						t.Fatalf("sizes: %+v vs %+v", got, want)
					}
					for i, c := range got.Clients {
						w := want.Clients[i]
						if c.ID != w.ID || c.Name != w.Name || c.Address != w.Address || c.RX != w.RX || c.TX != w.TX {
							t.Fatal("client mismatch", c, w)
						}
					}
					for i, p := range got.Points {
						w := want.Points[i]
						if p.At != w.At || p.ID != w.ID || math.Abs(p.RX-w.RX) > 1e-9 || math.Abs(p.TX-w.TX) > 1e-9 {
							t.Fatal("point mismatch", p, w)
						}
					}
				}
			}
		}
	}
	check()
	var rows int
	if e = h.db.QueryRow("SELECT COUNT(*) FROM traffic").Scan(&rows); e != nil {
		t.Fatal(e)
	}
	if rows > 10 {
		t.Errorf("idle samples still occupy one traffic row per poll: %d", rows)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	h, e = NewClientHistory(path, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	check()
}

func BenchmarkIdleHistoryPersistence(b *testing.B) {
	for _, n := range []int{4, 327} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			h, e := NewClientHistory(filepath.Join(b.TempDir(), "history.db"), nil, nil, nil)
			if e != nil {
				b.Fatal(e)
			}
			defer h.Close()
			values := make([]ClientCounter, n)
			for i := range values {
				values[i] = ClientCounter{ID: fmt.Sprint(i), Name: "idle", Address: fmt.Sprintf("192.0.%d.%d", i/250, i%250+1)}
			}
			now := time.Unix(1800000000, 0)
			h.persist(now, values)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				now = now.Add(30 * time.Second)
				if e = h.persist(now, values); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

func TestIdleHistoryRollbackRetryAndRetention(t *testing.T) {
	h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	start := time.Unix(1800000000, 0)
	values := []ClientCounter{{ID: "a", Name: "before", Address: "192.0.2.2"}}
	if e = h.persist(start, values); e != nil {
		t.Fatal(e)
	}
	if _, e = h.db.Exec("CREATE TRIGGER reject_idle BEFORE INSERT ON traffic_idle BEGIN SELECT RAISE(ABORT,'test write failure'); END"); e != nil {
		t.Fatal(e)
	}
	values[0].Name = "after"
	if e = h.persist(start.Add(30*time.Second), values); e == nil {
		t.Fatal("failed write accepted")
	}
	var count int
	if e = h.db.QueryRow("SELECT COUNT(*) FROM traffic_idle_clients").Scan(&count); e != nil || count != 0 {
		t.Fatal("metadata escaped transaction", count, e)
	}
	if h.baseline["192.0.2.2|a"].Name != "before" {
		t.Fatal("failed write advanced baseline")
	}
	if _, e = h.db.Exec("DROP TRIGGER reject_idle"); e != nil {
		t.Fatal(e)
	}
	if e = h.persist(start.Add(30*time.Second), values); e != nil {
		t.Fatal(e)
	}
	if e = h.db.QueryRow("SELECT COUNT(*) FROM traffic_idle").Scan(&count); e != nil || count != 1 {
		t.Fatal("retry lost/duplicated sample", count, e)
	}
	if e = h.persist(start.Add(30*time.Second), values); e != nil {
		t.Fatal(e)
	}
	if e = h.db.QueryRow("SELECT COUNT(*) FROM traffic_idle").Scan(&count); e != nil || count != 1 {
		t.Fatal("repeated observation duplicated sample", count, e)
	}
	if e = h.prune(start.Add(8 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"traffic_idle", "traffic_idle_clients"} {
		if e = h.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("expired idle remains", table, count, e)
		}
	}
}

func TestIdleHistoryKeepsDNSOnlyClients(t *testing.T) {
	h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	now := time.Unix(1800000000, 0)
	v := ClientCounter{ID: "dns-only", Name: "device", Address: "192.0.2.2"}
	h.enabled = true
	h.addresses[v.Address] = v
	if e = h.persist(now, []ClientCounter{v}); e != nil {
		t.Fatal(e)
	}
	h.AddDNS(now.Add(time.Second), v.Address, "example.test")
	if e = h.persist(now.Add(30*time.Second), []ClientCounter{v}); e != nil {
		t.Fatal(e)
	}
	r, e := h.Report(context.Background(), now, now.Add(time.Minute), nil, true)
	if e != nil || len(r.Clients) != 1 || r.Clients[0].Queries != 1 || len(r.Domains) != 1 || r.Domains[0].Domain != "example.test" {
		t.Fatalf("DNS-only history lost: %+v %v", r, e)
	}
}

func TestIdleHistoryStorageCosts(t *testing.T) {
	if os.Getenv("NETOS_HISTORY_COST") != "1" {
		t.Skip("explicit storage measurement")
	}
	for _, fixture := range []struct{ clients, samples int }{{4, 20160}, {327, 600}, {327, 20160}} {
		n, samples := fixture.clients, fixture.samples
		for _, legacy := range []bool{true, false} {
			if legacy && n == 327 && samples == 20160 {
				continue
			} // Beyond the old production row/page caps.
			t.Run(fmt.Sprintf("clients%d/samples%d/legacy%t", n, samples, legacy), func(t *testing.T) {
				h, e := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
				if e != nil {
					t.Fatal(e)
				}
				defer h.Close()
				// The oversized reference is for equal-input comparison only. Production
				// retains its page ceiling and compact-idle byte budget.
				if _, e = h.db.Exec("PRAGMA max_page_count=1048576"); e != nil {
					t.Fatal(e)
				}
				start := int64(1800000000)
				begin := time.Now()
				if legacy {
					_, e = h.db.Exec(`WITH RECURSIVE ticks(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ticks WHERE n<?), clients(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM clients WHERE n<?)
 INSERT INTO traffic SELECT ?+ticks.n*30,CAST(clients.n AS TEXT),'idle','192.0.2.2',0,0,30 FROM ticks CROSS JOIN clients`, samples, n, start)
				} else {
					ids := make([]int, n)
					for i := range ids {
						ids[i] = i + 1
						if _, e = h.db.Exec("INSERT INTO traffic_idle_clients(rowid,id,name,address,at) VALUES(?,?,'idle','192.0.2.2',?)", i+1, fmt.Sprint(i+1), start+int64(samples)*30); e != nil {
							t.Fatal(e)
						}
					}
					data, _ := json.Marshal(ids)
					_, e = h.db.Exec(`WITH RECURSIVE ticks(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ticks WHERE n<?) INSERT INTO traffic_idle SELECT ?+n*30,30,?,? FROM ticks`, samples, start, string(data), n)
				}
				if e != nil {
					t.Fatal(e)
				}
				var pages, size int64
				if e = h.db.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
					t.Fatal(e)
				}
				if e = h.db.QueryRow("PRAGMA page_size").Scan(&size); e != nil {
					t.Fatal(e)
				}
				t.Logf("fill=%s database_bytes=%d", time.Since(begin), pages*size)
				h.trafficCacheBlocked = true
				to := time.Unix(start+int64(samples)*30, 0)
				for _, minutes := range []int{3, 10080} {
					for _, points := range []bool{false, true} {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						begin = time.Now()
						r, _, e := h.reportTrafficSQL(ctx, to.Add(-time.Duration(minutes)*time.Minute), to, nil, points)
						cancel()
						if e != nil {
							t.Fatal(minutes, points, e)
						}
						if len(r.Clients) != n {
							t.Fatal("wrong fixture result", len(r.Clients), n)
						}
						for _, c := range r.Clients {
							if c.RX != 0 || c.TX != 0 {
								t.Fatal("fabricated idle traffic", c)
							}
						}
						for _, p := range r.Points {
							if p.RX != 0 || p.TX != 0 {
								t.Fatal("fabricated idle rate", p)
							}
						}
						t.Logf("minutes=%d points=%t duration=%s clients=%d points=%d", minutes, points, time.Since(begin), len(r.Clients), len(r.Points))
					}
				}
				h.trafficCacheBlocked = false
				h.trafficCache = nil
				for repeat := 0; repeat < 2; repeat++ {
					var before, after goruntime.MemStats
					goruntime.ReadMemStats(&before)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					begin = time.Now()
					r, e := h.Report(ctx, to.Add(-3*time.Minute), to, nil, false, ClientReportOptions{OmitPoints: true})
					elapsed := time.Since(begin)
					cancel()
					goruntime.ReadMemStats(&after)
					if e != nil {
						t.Fatal("summary call chain", e)
					}
					t.Logf("Report3min repeat=%d duration=%s allocated_bytes=%d clients=%d cache_blocked=%t", repeat, elapsed, after.TotalAlloc-before.TotalAlloc, len(r.Clients), h.trafficCacheBlocked)
				}
				if !legacy {
					begin = time.Now()
					if e = h.prune(to); e != nil {
						t.Fatal(e)
					}
					var bytes, rows int64
					if e = h.db.QueryRow("SELECT COALESCE(SUM(length(clients)+32),0),COUNT(*) FROM traffic_idle").Scan(&bytes, &rows); e != nil {
						t.Fatal(e)
					}
					t.Logf("prune=%s idle_budget_bytes=%d rows=%d limited=%t", time.Since(begin), bytes, rows, h.limited)
					if bytes > idleHistoryBudget {
						t.Fatal("idle byte budget exceeded")
					}
				}
			})
		}
	}
}
