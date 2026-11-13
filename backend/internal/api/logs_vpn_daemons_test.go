package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPNDaemonEvents(t *testing.T) {
	for _, tc := range []struct {
		unit, server, message, user, address, result string
		keep                                         bool
	}{
		{"netos-strongswan.service", "netos-srv7", "RADIUS authentication of 'alice' successful", "alice", "", "success", true},
		{"netos-strongswan.service", "netos-srv7", "RADIUS authentication of 'alice' failed", "alice", "", "failure", true},
		{"netos-strongswan.service", "netos-srv7", "IKE_SA netos-srv7[4] established between 192.0.2.1[server]...2001:db8::2[not-eap-user]", "", "2001:db8::2", "success", true},
		{"netos-strongswan.service", "netos-srv7", "deleting IKE_SA netos-srv7[4] between 192.0.2.1[server]...192.0.2.2[alice]", "", "192.0.2.2", "info", true},
		{"netos-strongswan.service", "netos-srv7", "authentication of 'server' (myself) with EAP successful", "", "", "", false},
		{"netos-strongswan.service", "netos-srv7", "scheduling rekeying in 3000s", "", "", "", false},
		{"netos-strongswan.service", "netos-srv7", "CHILD_SA netos-srv7{1} established with SPIs fake", "", "", "", false},
		{"netos-strongswan.service", "", "RADIUS authentication of 'alice' successful", "", "", "", false},
		{"netos-strongswan.service", "netos-ch7", "RADIUS authentication of 'alice' successful", "", "", "", false},
		{"netos-ikev2-ch7.service", "netos-srv7", "RADIUS authentication of 'alice' successful", "", "", "", false},
		{"netos-strongswan.service", "netos-srv7", "RADIUS authentication of unfamiliar format", "", "", "info", true},
		{"netos-vpn-l2tp-srv7.service", "", "Peer alice authenticated with CHAP", "alice", "", "success", true},
		{"netos-vpn-l2tp-srv7.service", "", "Peer alice failed CHAP authentication", "alice", "", "failure", true},
		{"netos-vpn-l2tp-srv7.service", "", "xl2tpd[123]: Connection established to 192.0.2.2, 1701. Local: 1, Remote: 2", "", "192.0.2.2", "info", true},
		{"netos-vpn-l2tp-srv7.service", "", "xl2tpd[123]: Connection 2 closed to 192.0.2.2, port 1701 (Server closing)", "", "192.0.2.2", "info", true},
		{"netos-vpn-l2tp-srv7.service", "", "local  IP address 10.0.0.1", "", "", "", false},
		{"netos-vpn-l2tp-srv7.service", "", "Peer alice authenticated with UNKNOWN", "", "", "info", true},
		{"session-1.scope", "", "Peer alice authenticated with CHAP", "", "", "", false},
	} {
		t.Run(tc.message+tc.unit+tc.server, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"_SYSTEMD_UNIT": tc.unit, "IKE_SA_NAME": tc.server, "MESSAGE": tc.message})
			rows, err := parseJournalEntries(string(raw), "vpn")
			if err != nil {
				t.Fatal(err)
			}
			if !tc.keep {
				if len(rows) != 0 {
					t.Fatal("invented event", rows)
				}
				return
			}
			if len(rows) != 1 {
				t.Fatal(rows)
			}
			e := rows[0]
			if e.Server != "srv7" || e.User != tc.user || e.Address != tc.address || e.Result != tc.result || e.Message != tc.message {
				t.Fatalf("wrong metadata %+v", e)
			}
		})
	}
}

func BenchmarkVPNMixedLogHandler(b *testing.B) {
	for _, n := range []int{30, 300} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var raw strings.Builder
			for i := 0; i < n; i++ {
				row := map[string]string{"__REALTIME_TIMESTAMP": vpnPageFixtureTime, "_SYSTEMD_UNIT": "netos-vpn-l2tp-srv7.service", "MESSAGE": "Peer alice authenticated with CHAP"}
				if i%2 == 0 {
					row["_SYSTEMD_UNIT"] = "netos-strongswan.service"
					row["IKE_SA_NAME"] = "netos-srv7"
					row["MESSAGE"] = "RADIUS authentication of 'alice' successful"
				}
				row["__CURSOR"] = fmt.Sprint("c", i)
				data, _ := json.Marshal(row)
				raw.Write(data)
				raw.WriteByte('\n')
			}
			s := &Server{StorageRunner: accessLogRunner{raw: raw.String()}}
			r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
			r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleLogs(w, r)
				if w.Code != 200 {
					b.Fatal(w.Code)
				}
			}
		})
	}
}
