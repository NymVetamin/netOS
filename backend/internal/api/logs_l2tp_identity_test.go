package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestL2TPIdentityFilterBeforeLimit(t *testing.T) {
	run := &pagedVPNRunner{}
	for i := 0; i < 150; i++ {
		id := "other"
		if i >= 120 {
			id = "wanted"
		}
		row := strings.ReplaceAll(vpnPageRow(i, "Peer alice authenticated with CHAP"), "netos-ocserv-srv12.service", "netos-vpn-l2tp-srv12.service")
		run.rows = append(run.rows, strings.TrimSuffix(row, "}")+`,"NETOS_VPN_SERVER_ID":"`+id+`"}`)
	}
	s := &Server{StorageRunner: run}
	w := httptest.NewRecorder()
	s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&object=wanted", nil))
	var page journalLogPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Entries) != 30 || run.calls != 1 {
		t.Fatal(w.Code, w.Body.String(), run.calls)
	}
	for _, entry := range page.Entries {
		if entry.Server != "wanted (srv12)" {
			t.Fatal(entry)
		}
	}
}

func BenchmarkL2TPIdentityPage(b *testing.B) {
	for _, n := range []int{30, 30000} {
		for _, metadata := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/metadata=%v", n, metadata), func(b *testing.B) {
				run := &pagedVPNRunner{}
				for i := 0; i < n; i++ {
					row := strings.ReplaceAll(vpnPageRow(i, "Peer alice authenticated with CHAP"), "netos-ocserv-srv12.service", "netos-vpn-l2tp-srv12.service")
					if metadata {
						row = strings.TrimSuffix(row, "}") + `,"NETOS_VPN_SERVER_ID":"server"}`
					}
					run.rows = append(run.rows, row)
				}
				s := &Server{StorageRunner: run}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					w := httptest.NewRecorder()
					s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&object=alice", nil))
					if w.Code != 200 {
						b.Fatal(w.Code)
					}
				}
				b.StopTimer()
				if run.calls != b.N {
					b.Fatal("extra commands", run.calls)
				}
			})
		}
	}
}

func TestL2TPHistoricalIdentity(t *testing.T) {
	for _, id := range []any{"old-server", "replacement-server", "", ".", "..", "bad\nFIELD=x", "a b", strings.Repeat("a", 65), []string{"old-server", "replacement-server"}, nil} {
		row := map[string]json.RawMessage{}
		for k, v := range map[string]any{"_SYSTEMD_UNIT": "netos-vpn-l2tp-srv12.service", "MESSAGE": "Peer alice authenticated with CHAP", "NETOS_VPN_SERVER_ID": id} {
			row[k], _ = json.Marshal(v)
		}
		want := "srv12"
		if id == "old-server" || id == "replacement-server" {
			want = id.(string) + " (srv12)"
		}
		vpn, ok := journalLogEntry(row, "vpn")
		all, allOK := allJournalEntry(row, false)
		if !ok || !allOK || vpn != all || vpn.Server != want || vpn.Protocol != "l2tp" || vpn.User != "alice" || vpn.Result != "success" {
			t.Fatalf("id=%v vpn=%+v all=%+v", id, vpn, all)
		}
		// The shared IKE daemon cannot identify a server with unit metadata.
		row["_SYSTEMD_UNIT"] = json.RawMessage(`"netos-strongswan.service"`)
		row["MESSAGE"] = json.RawMessage(`"RADIUS authentication of 'alice' successful"`)
		row["IKE_SA_NAME"] = json.RawMessage(`"netos-srv12"`)
		other, keep := journalLogEntry(row, "vpn")
		if !keep || other.Server != "srv12" {
			t.Fatal("metadata crossed protocol boundary", other)
		}
	}
}
