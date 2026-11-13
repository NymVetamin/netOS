package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPNLogEvents(t *testing.T) {
	for _, tc := range []struct{ message, user, address, result string }{
		{"main[alice]:192.0.2.2:50000 user logged in", "alice", "192.0.2.2", "success"},
		{"main[alice]:[2001:db8::2]:50000 user disconnected (reason: user disconnected, rx: 20, tx: 30)", "alice", "2001:db8::2", "info"},
		{"main[alice]:2001:db8::2:50000 user logged in", "alice", "2001:db8::2", "success"},
		{"worker[alice]: 192.0.2.2 worker-auth.c:1606: failed authentication for 'alice'", "alice", "192.0.2.2", "failure"},
		{"worker: 2001:db8::2 failed cookie authentication attempt", "", "2001:db8::2", "failure"},
	} {
		t.Run(tc.message, func(t *testing.T) {
			e := logEntry{Unit: "netos-ocserv-srv12.service", Message: tc.message}
			if !vpnLogFields(&e) || e.Protocol != "openconnect" || e.Server != "srv12" || e.User != tc.user || e.Address != tc.address || e.Result != tc.result || e.Message != tc.message {
				t.Fatalf("unexpected event: %+v", e)
			}
		})
	}
	for _, message := range []string{"", "sec-mod: using 'plain' authentication to authenticate user", "worker: 192.0.2.1 unrelated"} {
		e := logEntry{Unit: "netos-ocserv-srv1.service", Message: message}
		if vpnLogFields(&e) {
			t.Fatalf("invented event: %+v", e)
		}
	}
	for _, message := range []string{"main[user logged in]:192.0.2.1:42 new user session", "main[alice]:192.0.2.1:42 user logged in maybe", "unknown format: user disconnected"} {
		e := logEntry{Unit: "netos-ocserv-srv1.service", Message: message}
		if !vpnLogFields(&e) || e.Result != "info" || e.Message != message {
			t.Fatalf("unknown format misclassified: %+v", e)
		}
	}
	for _, unit := range []string{"netos-openconnect-ch1.service", "netos-xray-ch1.service", "ocserv.service", "netos-ocserv-srvx.service", ""} {
		e := logEntry{Unit: unit, Message: "main[alice]:192.0.2.1:42 user logged in"}
		if vpnLogFields(&e) {
			t.Fatalf("foreign/outbound unit: %+v", e)
		}
	}
}

func TestVPNLogsReadAndRetry(t *testing.T) {
	s := &Server{StorageRunner: accessLogRunner{fail: true}}
	read := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, r)
		return w
	}
	w := read()
	if w.Code != 502 || !strings.Contains(w.Body.String(), "Не удалось прочитать журнал VPN") {
		t.Fatal(w.Code, w.Body.String())
	}
	s.StorageRunner = accessLogRunner{raw: vpnPageRow(0, "main[alice]:192.0.2.2:42 user logged in")}
	for i := 0; i < 2; i++ {
		w = read()
		var d struct {
			Entries  []logEntry
			Warnings []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 || len(d.Entries) != 1 || len(d.Warnings) != 0 || d.Entries[0].Server != "srv12" {
			t.Fatal(w.Body.String(), err)
		}
	}
}

func BenchmarkVPNLogHandler(b *testing.B) {
	for _, n := range []int{30, 300} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var lines []string
			for i := 0; i < n; i++ {
				lines = append(lines, vpnPageRow(i, "main[alice]:192.0.2.2:42 user logged in"))
			}
			raw := strings.Join(lines, "\n")
			s := &Server{StorageRunner: accessLogRunner{raw: raw}}
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
