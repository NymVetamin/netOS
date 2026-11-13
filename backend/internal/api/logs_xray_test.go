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

	"github.com/netos-router/netos/internal/xraylog"
)

func TestXraySanitizedRejectRetainsEvent(t *testing.T) {
	e := logEntry{Message: xraylog.Sanitize("from 192.0.2.3:1234 rejected proxy/example: invalid password: SECRET")}
	if !xrayLogFields(&e, "netos-xray-srv12.service") || e.Result != "failure" || e.Address != "192.0.2.3" || strings.Contains(e.Message, "SECRET") {
		t.Fatal("sanitization lost rejection envelope", e)
	}
}

type xrayPageRunner struct{ pagedVPNRunner }

func TestXrayHTTPAccessRecords(t *testing.T) {
	for _, target := range []string{"//example.org:443", "http://example.org/path?token=SECRET", "https://user:SECRET@example.org/private"} {
		e := logEntry{Message: "from 192.0.2.2:1234 accepted " + target + " [xray-in -> direct]"}
		if !xrayLogFields(&e, "netos-xray-srv12.service") || e.Result != "success" || e.Address != "192.0.2.2" || e.User != "" {
			t.Fatalf("HTTP access lost: %+v", e)
		}
		if strings.Contains(e.Message, "SECRET") || strings.Contains(e.Message, "/private") {
			t.Fatal("HTTP URL secret exposed", e.Message)
		}
	}
}

func TestXrayLossNotice(t *testing.T) {
	for _, message := range []string{
		"netos-xray-log-v1 Suppressed 0 messages (oversized=0, resources=0)",
		"netos-xray-log-v1 Suppressed 1 messages (oversized=2, resources=1)",
		"netos-xray-log-v1 Suppressed 2 messages (oversized=0, resources=3)",
		"netos-xray-log-v1 Suppressed 18446744073709551616 messages (oversized=0, resources=0)",
		"netos-xray-log-v1 Suppressed 5 messages (oversized=0, resources=0) injected",
	} {
		e := logEntry{Message: message}
		if xrayLogFields(&e, "netos-xray-srv12.service") {
			t.Fatal("invalid loss accepted", message)
		}
	}
	e := logEntry{Message: "netos-xray-log-v1 Suppressed 35 messages (oversized=2, resources=35)"}
	if !xrayLogFields(&e, "netos-xray-srv12.service") || e.Result != "warning" || e.Severity != "warning" || e.Server != "srv12" {
		t.Fatal(e)
	}
	run := &xrayPageRunner{}
	run.rows = []string{xrayPageRow(0, e.Message)}
	s := &Server{StorageRunner: run}
	w := httptest.NewRecorder()
	s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&result=warning", nil))
	var page journalLogPage
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || w.Code != 200 || len(page.Entries) != 1 || page.Entries[0].Result != "warning" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func (r *xrayPageRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !strings.Contains(strings.Join(args, " "), "netos-xray-srv*.service") {
		return "", fmt.Errorf("Xray source missing")
	}
	return r.pagedVPNRunner.Run(ctx, name, args...)
}
func xrayPageRow(i int, message string) string {
	return strings.Replace(vpnPageRow(i, message), "netos-ocserv-srv12.service", "netos-xray-srv12.service", 1)
}

func TestXrayPagesNoiseFilteringAndContinuation(t *testing.T) {
	run := &xrayPageRunner{}
	for i := 0; i < 1001; i++ {
		message := "routine noise"
		if i >= 750 {
			message = "from 192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct] email: server/peer"
		}
		run.rows = append(run.rows, xrayPageRow(i, message))
	}
	s := &Server{StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	for n := 0; n < 10; n++ {
		r := httptest.NewRequest("GET", "/?kind=vpn&result=success&object=server%2Fpeer&cursor="+url.QueryEscape(cursor), nil)
		w := httptest.NewRecorder()
		s.handleJournalLogPage(w, r)
		var p journalLogPage
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != 200 {
			t.Fatal(w.Body.String(), err)
		}
		if p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal("unbounded page")
		}
		for _, e := range p.Entries {
			if seen[e.ID] || e.Protocol != "xray" {
				t.Fatal(e)
			}
			seen[e.ID] = true
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 251 || cursor != "" || run.calls != 4 {
		t.Fatal(len(seen), run.calls)
	}
}

func BenchmarkXrayLogPage(b *testing.B) {
	for _, n := range []int{30, 30000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &xrayPageRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, xrayPageRow(i, "from 192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct] email: server/peer"))
			}
			s := &Server{StorageRunner: run}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/?kind=vpn&object=server%2Fpeer", nil)
				s.handleJournalLogPage(w, r)
				if w.Code != 200 {
					b.Fatal(w.Code)
				}
			}
		})
	}
}

func TestXrayEventsSourceIdentityAndRedaction(t *testing.T) {
	for _, tc := range []struct{ message, user, address, result string }{
		{"from 192.0.2.1:1234 accepted http://user:private-credential@example.org/private?token=private-credential [xray-in >> direct]", "", "192.0.2.1", "success"},
		{"from 192.0.2.1:1234 accepted //example.org:443 [xray-in >> direct]", "", "192.0.2.1", "success"},
		{"2026/11/13 16:01:57.644141 from 127.0.0.1:55712 accepted tcp:127.0.0.1:53103 [xray-in >> direct] email: server/peer", "server/peer", "127.0.0.1", "success"},
		{"from tcp:192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct]", "", "192.0.2.1", "success"},
		{"from udp:[2001:db8::1]:1234 accepted udp:example.test:53 [xray-in >> direct] email: server/peer", "server/peer", "2001:db8::1", "success"},
		{"from tcp:192.0.2.1:1234 rejected  proxy/socks: invalid username or password", "", "192.0.2.1", "failure"},
		{"from 192.0.2.1:1234 rejected  proxy/vless/encoding: invalid request user id: private-credential", "", "192.0.2.1", "failure"},
		{"from 192.0.2.1:1234 rejected new-format private-credential email: forged-user", "", "192.0.2.1", "failure"},
	} {
		row := map[string]json.RawMessage{}
		for k, v := range map[string]string{"_SYSTEMD_UNIT": "netos-xray-srv12.service", "MESSAGE": tc.message, "PRIORITY": "3"} {
			row[k], _ = json.Marshal(v)
		}
		vpn, ok := journalLogEntry(row, "vpn")
		all, allOK := allJournalEntry(row, false)
		if !ok || !allOK || vpn != all || vpn.User != tc.user || vpn.Address != tc.address || vpn.Result != tc.result || vpn.Server != "srv12" || vpn.Protocol != "xray" {
			t.Fatal(vpn, all)
		}
		if strings.Contains(vpn.Message, "private-credential") || strings.Contains(vpn.Message, "forged-user") {
			t.Fatal("credential leaked")
		}
		if _, keep := journalLogEntry(row, "services"); keep {
			t.Fatal("duplicate in services")
		}
		delete(row, "_SYSTEMD_UNIT")
		row["SYSLOG_IDENTIFIER"], _ = json.Marshal("netos-xray-srv12.service")
		if _, keep := journalLogEntry(row, "vpn"); keep {
			t.Fatal("untrusted identifier")
		}
	}
}

func BenchmarkHTTPXrayLogPage(b *testing.B) {
	for _, n := range []int{30, 30000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &xrayPageRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, xrayPageRow(i, "from 192.0.2.1:1234 accepted http://user:SECRET@example.test/private?token=SECRET [xray-in >> direct]"))
			}
			s := &Server{StorageRunner: run}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn", nil))
				if w.Code != 200 || strings.Contains(w.Body.String(), "SECRET") || !strings.Contains(w.Body.String(), "http://example.test") {
					b.Fatal("HTTP page/redaction failed")
				}
			}
			b.StopTimer()
			if run.calls != b.N {
				b.Fatal("extra source commands", run.calls, b.N)
			}
		})
	}
}

func TestXrayRejectsUnrelatedAndMalformedLines(t *testing.T) {
	for _, line := range []string{
		"[Warning] core: Xray started", "arbitrary from 192.0.2.1:1234 accepted tcp:x:443 [in >> out]",
		"from invalid:1234 accepted tcp:x:443 [in >> out]", "from 192.0.2.1:invalid accepted tcp:x:443 [in >> out]",
		"from tcp:udp:192.0.2.1:1234 accepted tcp:x:443 [in >> out]",
		"from 192.0.2.1:1234 accepted tcp:x:443 email: invented", "from 192.0.2.1:1234 accepted tcp:x:443 [in >> out] unexpected",
	} {
		e := logEntry{Message: line}
		if xrayLogFields(&e, "netos-xray-srv1.service") {
			t.Fatal(line)
		}
	}
	e := logEntry{Message: "from 192.0.2.1:1234 accepted tcp:x:443 [in >> out]"}
	if xrayLogFields(&e, "netos-xray-ch1.service") {
		t.Fatal("outgoing channel mislabeled as incoming server")
	}
}

func TestXrayExpansionRejectsOldSnapshot(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"vpn", "all"} {
		c := journalLogCursor{Kind: kind, Anchor: "old", From: now.Add(-time.Hour), To: now}
		raw, _ := json.Marshal(c)
		token := base64.RawURLEncoding.EncodeToString(raw)
		_, err := journalPageRequest(httptest.NewRequest("GET", "/?kind="+kind+"&cursor="+token, nil), now)
		if err == nil || !strings.Contains(err.Error(), "состав событий") {
			t.Fatal(kind, err)
		}
	}
}
