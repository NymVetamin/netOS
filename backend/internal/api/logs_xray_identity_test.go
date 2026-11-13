package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func BenchmarkXrayIdentityPage(b *testing.B) {
	for _, n := range []int{30, 30000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			run := &xrayPageRunner{}
			for i := 0; i < n; i++ {
				row := xrayPageRow(i, "from 192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct] email: server/peer")
				row = strings.TrimSuffix(row, "}") + `,"NETOS_XRAY_SERVER_ID":"server","NETOS_XRAY_PROTOCOL":"socks"}`
				run.rows = append(run.rows, row)
			}
			s := &Server{StorageRunner: run}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&object=server%2Fpeer", nil))
				if w.Code != 200 || !strings.Contains(w.Body.String(), `"protocol":"xray/socks"`) {
					b.Fatal("metadata page failed", w.Code)
				}
			}
			b.StopTimer()
			if run.calls != b.N {
				b.Fatal("extra source commands", run.calls, b.N)
			}
		})
	}
}

func TestXrayHistoricalIdentity(t *testing.T) {
	for _, message := range []string{
		"from 192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct]",
		"from 192.0.2.1:1234 rejected invalid password: SECRET",
		"netos-xray-log-v1 Suppressed 2 messages (oversized=0, resources=2)",
	} {
		for _, id := range []string{"first-server", "replacement-server"} {
			row := map[string]json.RawMessage{}
			for k, v := range map[string]string{"MESSAGE": message, "_SYSTEMD_UNIT": "netos-xray-srv12.service", "NETOS_XRAY_SERVER_ID": id, "NETOS_XRAY_PROTOCOL": "socks"} {
				row[k], _ = json.Marshal(v)
			}
			vpn, ok := journalLogEntry(row, "vpn")
			all, allOK := allJournalEntry(row, false)
			if !ok || !allOK || vpn != all || vpn.Server != id+" (srv12)" || vpn.Protocol != "xray/socks" {
				t.Fatalf("event identity lost: %+v / %+v", vpn, all)
			}
			if _, keep := journalLogEntry(row, "services"); keep {
				t.Fatal("event duplicated in Services")
			}
			for _, bad := range []json.RawMessage{nil, json.RawMessage(`""`), json.RawMessage(`["socks","http"]`), json.RawMessage(`"unknown"`)} {
				row["NETOS_XRAY_PROTOCOL"] = bad
				fallback, keep := journalLogEntry(row, "vpn")
				if !keep || fallback.Server != "srv12" || fallback.Protocol != "xray" {
					t.Fatal("unreliable metadata must retain historical fallback", fallback)
				}
			}
		}
	}
}

func TestXrayIdentityFilterBeforePageLimit(t *testing.T) {
	run := &xrayPageRunner{}
	for i := 0; i < 150; i++ {
		row := map[string]json.RawMessage{}
		json.Unmarshal([]byte(xrayPageRow(i, "from 192.0.2.1:1234 accepted tcp:example.test:443 [xray-in >> direct]")), &row)
		id := "other"
		if i >= 120 {
			id = "wanted"
		}
		row["NETOS_XRAY_SERVER_ID"], _ = json.Marshal(id)
		row["NETOS_XRAY_PROTOCOL"] = json.RawMessage(`"socks"`)
		data, _ := json.Marshal(row)
		run.rows = append(run.rows, string(data))
	}
	s := &Server{StorageRunner: run}
	w := httptest.NewRecorder()
	s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&object=wanted", nil))
	var page journalLogPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Entries) != 30 || run.calls != 1 {
		t.Fatal("identity filtering failed", w.Code, w.Body.String(), run.calls)
	}
	for _, entry := range page.Entries {
		if entry.Server != "wanted (srv12)" || entry.Protocol != "xray/socks" {
			t.Fatal(entry)
		}
	}
}

func TestXrayMalformedServerIdentity(t *testing.T) {
	for _, bad := range []json.RawMessage{nil, json.RawMessage(`""`), json.RawMessage(`["a","b"]`), json.RawMessage(`"%n"`), json.RawMessage(`"line\nbreak"`), json.RawMessage(`"` + strings.Repeat("a", 65) + `"`)} {
		row := map[string]json.RawMessage{
			"MESSAGE":              json.RawMessage(`"from 192.0.2.1:1234 rejected secret"`),
			"_SYSTEMD_UNIT":        json.RawMessage(`"netos-xray-srv12.service"`),
			"NETOS_XRAY_SERVER_ID": bad, "NETOS_XRAY_PROTOCOL": json.RawMessage(`"socks"`),
		}
		e, ok := journalLogEntry(row, "vpn")
		if !ok || e.Server != "srv12" || e.Protocol != "xray" || strings.Contains(e.Message, "secret") {
			t.Fatal("malformed metadata broke fallback/redaction", e)
		}
	}
}
