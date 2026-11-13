package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func servicePageRow(i int, priority, message string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("c", i), "__REALTIME_TIMESTAMP": vpnPageFixtureTime, "_SYSTEMD_UNIT": "netosd.service", "PRIORITY": priority, "MESSAGE": message})
	return string(b)
}

func TestServicePagesPreserveWarningsAndBindSource(t *testing.T) {
	run := &pagedVPNRunner{}
	for i := 0; i < 750; i++ {
		run.rows = append(run.rows, servicePageRow(i, "6", "routine info"))
	}
	for i := 750; i < 1001; i++ {
		run.rows = append(run.rows, servicePageRow(i, "6", "[пред] fixture warning"))
	}
	s := &Server{StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		r := httptest.NewRequest("GET", "/api/logs?kind=services&result=warning&object=netosd&cursor="+url.QueryEscape(cursor), nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, r)
		var d journalLogPage
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
			t.Fatal(w.Body.String(), err)
		}
		if d.Kind != "services" || d.Scanned > logScanSize || len(d.Entries) > logPageSize {
			t.Fatal(d)
		}
		if page == 0 && d.Next == "" {
			t.Fatal("noise hid continuation")
		}
		for _, e := range d.Entries {
			if seen[e.ID] || e.Severity != "warning" || e.Unit != "netosd.service" {
				t.Fatal(e)
			}
			seen[e.ID] = true
		}
		if page == 0 {
			wrong := httptest.NewRequest("GET", "/?kind=vpn&result=warning&object=netosd&cursor="+url.QueryEscape(d.Next), nil)
			if _, err := journalPageRequest(wrong, time.Now()); err == nil {
				t.Fatal("cross-source cursor accepted")
			}
		}
		cursor = d.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 251 || cursor != "" || run.calls != 4 {
		t.Fatal(len(seen), run.calls, cursor)
	}
}

func TestServicePageTypesAndLegacyVPNToken(t *testing.T) {
	now := time.Now().UTC()
	c := journalLogCursor{Kind: "services", From: now.Add(-time.Hour), To: now, Result: "error", Object: "netosd"}
	raw := servicePageRow(0, "6", "[пред] warning") + "\n" + servicePageRow(1, "6", "[ошиб] failure") + "\n" + servicePageRow(2, "3", "daemon failure")
	p, _, err := readJournalLogPage(raw, c)
	if err != nil || len(p.Entries) != 2 {
		t.Fatal(p, err)
	}
	for _, result := range []string{"success", "failure"} {
		if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=services&result="+result, nil), now); err == nil {
			t.Fatal("invalid service type accepted", result)
		}
	}
	legacy, _ := json.Marshal(map[string]any{"anchor": "c0", "from": c.From, "to": c.To, "result": "", "object": ""})
	token := base64.RawURLEncoding.EncodeToString(legacy)
	if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=vpn&cursor="+token, nil), now); err == nil {
		t.Fatal("pre-Xray VPN snapshot accepted after expanding event sources")
	}
	if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=services&cursor="+token, nil), now); err == nil {
		t.Fatal("legacy VPN token accepted for services")
	}
	// info is valid for both sources: rejection must be caused by the source,
	// not by an incompatible severity filter.
	bound, _ := json.Marshal(journalLogCursor{Kind: "services", Anchor: "c0", From: c.From, To: c.To, Result: "info"})
	if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=vpn&result=info&cursor="+base64.RawURLEncoding.EncodeToString(bound), nil), now); err == nil {
		t.Fatal("service cursor accepted for VPN")
	}
}

func BenchmarkServicePage(b *testing.B) {
	for _, n := range []int{30, 3000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &pagedVPNRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, servicePageRow(i, "4", "warning"))
			}
			s := &Server{StorageRunner: run}
			r := httptest.NewRequest("GET", "/api/logs?kind=services", nil)
			r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleLogs(w, r)
				if w.Code != 200 || !strings.Contains(w.Body.String(), `"kind":"services"`) {
					b.Fatal(w.Body.String())
				}
			}
		})
	}
}

func TestServiceCursorRejectsPreviousSourceSet(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"services", "all", "vpn"} {
		old, _ := json.Marshal(journalLogCursor{Schema: 3, Kind: kind, Anchor: "c0", From: now.Add(-time.Hour), To: now})
		request := httptest.NewRequest("GET", "/?kind="+kind+"&cursor="+base64.RawURLEncoding.EncodeToString(old), nil)
		if _, err := journalPageRequest(request, now); err == nil || !strings.Contains(err.Error(), "состав событий") {
			t.Fatalf("old snapshot not rejected for source change: %s %v", kind, err)
		}
	}
}

func BenchmarkLegacyXrayServicePage(b *testing.B) {
	for _, n := range []int{30, 30000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &pagedVPNRunner{}
			for i := 0; i < n; i++ {
				message := "from 192.0.2.2:1234 accepted tcp:example.org:443 [in -> out]"
				if i == 0 {
					message = "[Warning] core: started"
				}
				row, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("c", i), "__REALTIME_TIMESTAMP": vpnPageFixtureTime, "_SYSTEMD_UNIT": "netos-xray-ch12.service", "PRIORITY": "6", "MESSAGE": message})
				run.rows = append(run.rows, string(row))
			}
			s := &Server{StorageRunner: run}
			r := httptest.NewRequest("GET", "/api/logs?kind=services", nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleJournalLogPage(w, r)
				if w.Code != 200 || !strings.Contains(w.Body.String(), "[Warning] core: started") {
					b.Fatal(w.Body.String())
				}
			}
			b.StopTimer()
			if run.calls != b.N {
				b.Fatal("extra queries", run.calls, b.N)
			}
		})
	}
}
