package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestResourceHistoryUsesObservationSecond(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.enabled = true
	const client = "ip:192.0.2.1"
	for _, second := range []int64{105, 115, 105} {
		at := time.Unix(second, 0)
		h.AddDNS(at, "192.0.2.1", "example.test")
		h.addXrayResources([]xrayResource{{client: client, domain: "example.test", source: "xray-dns", at: at}})
	}
	// Ambiguous historical aggregates retain their previous attribution.
	if _, err = h.db.Exec("INSERT INTO domains VALUES(130,?,'legacy.test',3,105,115)", client); err != nil {
		t.Fatal(err)
	}
	if _, err = h.db.Exec("CREATE TRIGGER fail_resources BEFORE INSERT ON resources BEGIN SELECT RAISE(ABORT,'retry'); END"); err != nil {
		t.Fatal(err)
	}
	if err = h.persist(time.Unix(125, 0), nil); err == nil {
		t.Fatal("expected insert failure")
	}
	if _, err = h.db.Exec("DROP TRIGGER fail_resources"); err != nil {
		t.Fatal(err)
	}
	for _, second := range []int64{130, 140} {
		if err = h.persist(time.Unix(second, 0), nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ from, to, dns, resources int64 }{{105, 105, 2, 2}, {106, 114, 0, 0}, {115, 115, 1, 1}, {125, 140, 3, 0}, {100, 140, 6, 3}} {
		report, err := h.Report(context.Background(), time.Unix(tc.from, 0), time.Unix(tc.to, 0), []string{client}, true)
		if err != nil {
			t.Fatal(err)
		}
		var dns, resources int64
		for _, d := range report.Domains {
			if d.Source == "dns" {
				dns += d.Count
			} else {
				resources += d.Count
			}
			if tc.from == tc.to && (d.First != tc.from || d.Last != tc.to) {
				t.Fatalf("wrong observation times: %+v", d)
			}
		}
		if dns != tc.dns || resources != tc.resources {
			t.Errorf("%d..%d: dns=%d resources=%d want %d/%d", tc.from, tc.to, dns, resources, tc.dns, tc.resources)
		}
	}
}

func TestResourceHistoryBufferLimitPerSecond(t *testing.T) {
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.enabled = true
	start := time.Now().Truncate(time.Second)
	add := func(i int) {
		at := start.Add(time.Duration(i) * time.Second)
		h.AddDNS(at, "192.0.2.1", "example.test")
		h.addXrayResources([]xrayResource{{client: "client", domain: "example.test", source: "xray", at: at}})
	}
	for i := 0; i <= 4096; i++ {
		add(i)
	}
	add(0)
	if len(h.dns) != 4096 || len(h.resources) != 4096 {
		t.Fatalf("buffer sizes %d/%d", len(h.dns), len(h.resources))
	}
	if err = h.persist(start.Add(4100*time.Second), nil); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"domains", "resources"} {
		var rows, total int
		if err = h.db.QueryRow("SELECT COUNT(*),SUM(n) FROM "+table).Scan(&rows, &total); err != nil || rows != 4096 || total != 4097 {
			t.Fatalf("%s rows=%d total=%d err=%v", table, rows, total, err)
		}
	}
	dropped := start.Unix() + 4096
	limits := h.reportLimits(dropped, dropped)
	if len(limits) != 2 || limits[0].Kind != "dns-buffer" || limits[1].Kind != "resource-buffer" {
		t.Fatalf("losses %+v", limits)
	}
}
