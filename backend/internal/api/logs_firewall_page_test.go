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

func firewallPageRow(i int, message string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("c", i), "__REALTIME_TIMESTAMP": vpnPageFixtureTime, "SYSLOG_IDENTIFIER": "kernel", "MESSAGE": message})
	return string(b)
}

type firewallPageRunner struct{ pagedVPNRunner }

func (r *firewallPageRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !strings.Contains(strings.Join(args, " "), "_TRANSPORT=kernel") {
		return "", fmt.Errorf("missing kernel selection")
	}
	for _, a := range args {
		if a == "-k" || strings.HasPrefix(a, "--boot") || strings.Contains(a, "IKE_SA_NAME") {
			return "", fmt.Errorf("unexpected scope %s", a)
		}
	}
	return r.pagedVPNRunner.Run(ctx, name, args...)
}

func TestFirewallPagesPreserveHistoryAndFilter(t *testing.T) {
	run := &firewallPageRunner{}
	for i := 0; i < 750; i++ {
		run.rows = append(run.rows, firewallPageRow(i, "unrelated kernel message"))
	}
	for i := 750; i < 1101; i++ {
		run.rows = append(run.rows, firewallPageRow(i, "netos qa-rule: IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 PROTO=UDP DPT=54321"))
	}
	s := &Server{StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		req := httptest.NewRequest("GET", "/api/logs?kind=firewall&object="+url.QueryEscape("DPT=54321")+"&cursor="+url.QueryEscape(cursor), nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, req)
		var p journalLogPage
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 {
			t.Fatal(w.Code, w.Body.String(), err)
		}
		if p.Kind != "firewall" || p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal(p)
		}
		if page == 0 && (len(p.Entries) != 0 || p.Next == "") {
			t.Fatal("noise hid history")
		}
		for _, e := range p.Entries {
			if seen[e.ID] || e.Unit != "kernel" || e.Result != "" || e.Source != "firewall" || !strings.Contains(e.Message, "DPT=54321") {
				t.Fatal(e)
			}
			seen[e.ID] = true
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 351 || cursor != "" || run.calls != 5 {
		t.Fatal(len(seen), run.calls, cursor)
	}
}

func TestFirewallPageFiltersAndRetry(t *testing.T) {
	now := time.Now().UTC()
	c := journalLogCursor{Kind: "firewall", From: now.Add(-time.Hour), To: now, Result: "info", Object: "dst=192.0.2.2"}
	rows := []string{}
	for i := 0; i < 150; i++ {
		rows = append(rows, firewallPageRow(i, "netos other: DST=192.0.2.1"))
	}
	raw := firewallPageRow(150, "netos selected: DST=192.0.2.2")
	rows = append(rows, raw)
	p, _, err := readJournalLogPage(strings.Join(rows, "\n"), c)
	if err != nil || len(p.Entries) != 1 || p.Entries[0].ID != "c150" {
		t.Fatal(p, err)
	}
	for _, result := range []string{"success", "failure", "warning", "error"} {
		if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=firewall&result="+result, nil), now); err == nil {
			t.Fatal("fabricated verdict accepted", result)
		}
	}
	c.Anchor = "c150"
	token, _ := json.Marshal(c)
	for _, kind := range []string{"vpn", "services"} {
		req := httptest.NewRequest("GET", "/?kind="+kind+"&result=info&object=dst%3D192.0.2.2&cursor="+base64.RawURLEncoding.EncodeToString(token), nil)
		if _, err := journalPageRequest(req, now); err == nil {
			t.Fatal("firewall cursor accepted for", kind)
		}
	}
	s := &Server{StorageRunner: overflowingLogRunner{accessLogRunner{raw: raw}}}
	for attempt := 0; attempt < 3; attempt++ {
		req := httptest.NewRequest("GET", "/api/logs?kind=firewall", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, req)
		if attempt == 0 {
			if w.Code != 502 {
				t.Fatal(w.Body.String())
			}
		} else {
			var got journalLogPage
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || w.Code != 200 || len(got.Entries) != 1 || got.Entries[0].Message != "netos selected: DST=192.0.2.2" {
				t.Fatal(w.Body.String())
			}
		}
		s.StorageRunner = accessLogRunner{raw: raw}
	}
}

func BenchmarkFirewallPage(b *testing.B) {
	for _, n := range []int{30, 3000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &firewallPageRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, firewallPageRow(i, "netos qa-rule: IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 PROTO=UDP DPT=54321"))
			}
			s := &Server{StorageRunner: run}
			r := httptest.NewRequest("GET", "/api/logs?kind=firewall&object=54321", nil)
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
