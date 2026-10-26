package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestClientReportWithoutPointsPreservesOtherFields(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Unix(1800000000, 0)
	for i := 0; i < 7; i++ {
		id := fmt.Sprint(i)
		for n := 0; n < 5; n++ {
			if _, err = h.db.Exec("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)", now.Unix()-int64(n*30), id, "client"+id, "192.0.2.1", (i+1)*100, n*10, 30); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = h.db.Exec("INSERT INTO domains VALUES(?,?,?,?,?,?)", now.Unix(), id, "example.com", i+1, now.Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err = h.db.Exec("INSERT INTO resources VALUES(?,?,?,?,?,?,?)", now.Unix(), id, "example.net", "xray-domain", i+2, now.Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	h.limited = true
	h.problem = "traffic problem"
	h.dnsProblem = "dns problem"
	for _, sqlFallback := range []bool{false, true} {
		h.trafficCache = nil
		h.trafficCacheBlocked = sqlFallback
		for _, enabled := range []bool{false, true} {
			h.enabled = enabled
			for _, details := range []bool{false, true} {
				for _, selected := range [][]string{nil, {"1"}, {"2", "2", "1"}, {"missing"}} {
					for _, from := range []time.Time{now.Add(-time.Hour), now.Add(time.Second)} {
						full, e := h.Report(context.Background(), from, now.Add(time.Minute), selected, details)
						if e != nil {
							t.Fatal(e)
						}
						light, e := h.Report(context.Background(), from, now.Add(time.Minute), selected, details, ClientReportOptions{OmitPoints: true})
						if e != nil {
							t.Fatal(e)
						}
						if from.Before(now) && len(selected) == 0 && len(full.Points) == 0 {
							t.Fatal("fixture has no points")
						}
						full.Points = []ClientPoint{}
						if !reflect.DeepEqual(full, light) {
							t.Fatalf("fallback=%v selected=%v details=%v: full=%+v light=%+v", sqlFallback, selected, details, full, light)
						}
					}
				}
			}
		}
		if _, err = h.Report(context.Background(), now.Add(-time.Hour), now, make([]string, 17), true, ClientReportOptions{OmitPoints: true}); err == nil {
			t.Fatal("selection limit bypassed")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = h.Report(ctx, now.Add(-time.Hour), now, nil, true, ClientReportOptions{OmitPoints: true}); err == nil {
			t.Fatal("cancellation ignored")
		}
	}
}
