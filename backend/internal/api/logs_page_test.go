package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type pagedVPNRunner struct {
	accessLogRunner
	rows  []string
	calls int
}

func (r *pagedVPNRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.calls++
	start, limit := 0, 0
	for i, a := range args {
		if strings.HasPrefix(a, "--grep") {
			return "", fmt.Errorf("unbounded grep")
		}
		if a == "-n" {
			limit, _ = strconv.Atoi(args[i+1])
		}
		if strings.HasPrefix(a, "--cursor=c") {
			start, _ = strconv.Atoi(strings.TrimPrefix(a, "--cursor=c"))
		}
	}
	if limit < 1 || limit > logScanSize+2 {
		return "", fmt.Errorf("unbounded count %d", limit)
	}
	if start >= len(r.rows) {
		return "", nil
	}
	return strings.Join(r.rows[start:min(start+limit, len(r.rows))], "\n"), nil
}

var vpnPageFixtureTime = strconv.FormatInt(time.Now().Add(-time.Minute).UnixMicro(), 10)

func vpnPageRow(i int, message string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("c", i), "__REALTIME_TIMESTAMP": vpnPageFixtureTime, "_SYSTEMD_UNIT": "netos-ocserv-srv12.service", "MESSAGE": message})
	return string(b)
}

func TestVPNPagesFilterBeforeLimitAndKeepAllEvents(t *testing.T) {
	run := &pagedVPNRunner{}
	for i := 0; i < 750; i++ {
		run.rows = append(run.rows, vpnPageRow(i, "noise"))
	}
	for i := 750; i < 1001; i++ {
		run.rows = append(run.rows, vpnPageRow(i, "main[alice]:192.0.2.2:42 user logged in"))
	}
	s := &Server{StorageRunner: run}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		r := httptest.NewRequest("GET", "/api/logs?kind=vpn&result=success&object=alice&cursor="+url.QueryEscape(cursor), nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, r)
		var p journalLogPage
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 {
			t.Fatal(w.Body.String(), err)
		}
		if p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal("unbounded page")
		}
		if page == 0 && (len(p.Entries) != 0 || p.Next == "") {
			t.Fatal("noise was mistaken for end of history")
		}
		for _, e := range p.Entries {
			if seen[e.ID] {
				t.Fatal("duplicate", e.ID)
			}
			seen[e.ID] = true
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 251 || cursor != "" || run.calls != 4 {
		t.Fatalf("events=%d calls=%d cursor=%q", len(seen), run.calls, cursor)
	}
}

func TestVPNPageCursorAndErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := journalLogCursor{Schema: 7, From: now.Add(-24 * time.Hour), To: now, Anchor: "c1"}
	if _, stale, err := readJournalLogPage(vpnPageRow(2, "noise"), c); err != nil || !stale {
		t.Fatal("missing anchor not rejected", stale, err)
	}
	if _, stale, err := readJournalLogPage("", c); err != nil || !stale {
		t.Fatal("empty stale cursor not rejected", stale, err)
	}
	if _, _, err := readJournalLogPage("{", c); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	c.Anchor = ""
	p, stale, err := readJournalLogPage(vpnPageRow(0, "main[alice]:192.0.2.2:42 user logged in"), c)
	if err != nil || stale || len(p.Entries) != 1 || p.Next != "" {
		t.Fatal(p, stale, err)
	}
	for _, q := range []string{"cursor=bad", "cursor=" + base64.RawURLEncoding.EncodeToString([]byte(`{"anchor":"c0"}`)), "result=unknown", "object=" + strings.Repeat("a", 129), "from=invalid", "from=2020-01-01T00:00:00Z", "to=2099-01-01T00:00:00Z"} {
		if _, err := journalPageRequest(httptest.NewRequest("GET", "/?"+q, nil), now); err == nil {
			t.Fatal("invalid request accepted", q)
		}
	}
	raw := []string{}
	for i := 0; i < 101; i++ {
		raw = append(raw, vpnPageRow(i, "main[alice]:192.0.2.2:42 user logged in"))
	}
	p, _, err = readJournalLogPage(strings.Join(raw, "\n"), c)
	if err != nil || p.Next == "" {
		t.Fatal(p, err)
	}
	got, err := journalPageRequest(httptest.NewRequest("GET", "/?cursor="+p.Next, nil), now.Add(time.Hour))
	if err != nil || !got.To.Equal(now) || got.Anchor != "c99" {
		t.Fatal(got, err)
	}
	if _, err := journalPageRequest(httptest.NewRequest("GET", "/?cursor="+p.Next+"&result=failure", nil), now); err == nil {
		t.Fatal("changed filter accepted")
	}
}

func BenchmarkVPNPage(b *testing.B) {
	for _, n := range []int{30, 3000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			run := &pagedVPNRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, vpnPageRow(i, "noise"))
			}
			run.rows = append(run.rows, vpnPageRow(n, "main[alice]:192.0.2.2:42 user logged in"))
			s := &Server{StorageRunner: run}
			r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
			r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleLogs(w, r)
				if w.Code != 200 {
					b.Fatal(w.Body.String())
				}
			}
		})
	}
}

func TestVPNPageRangeAndResultFilters(t *testing.T) {
	us, _ := strconv.ParseInt(vpnPageFixtureTime, 10, 64)
	at := time.UnixMicro(us)
	c := journalLogCursor{From: at, To: at.Add(time.Minute), Result: "failure", Object: "alice"}
	rows := []string{
		vpnPageRow(0, "main[alice]:192.0.2.2:42 user logged in"),
		vpnPageRow(1, "worker[bob]: 192.0.2.2 failed cookie authentication attempt"),
		vpnPageRow(2, "worker[alice]: 192.0.2.2 failed cookie authentication attempt"),
		strings.ReplaceAll(vpnPageRow(3, "worker[alice]: 192.0.2.2 failed cookie authentication attempt"), vpnPageFixtureTime, strconv.FormatInt(us-1, 10)),
	}
	p, stale, err := readJournalLogPage(strings.Join(rows, "\n"), c)
	if err != nil || stale || len(p.Entries) != 1 || p.Entries[0].ID != "c2" || p.Next != "" {
		t.Fatal(p, stale, err)
	}
}
