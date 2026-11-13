package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHandshakeJournalPipelineAndSourceBoundaries(t *testing.T) {
	var observer vpnHandshakeObserver
	logger := &lifecycleLogger{}
	s := &Server{Logger: logger}
	samples := handshakeSamples(70)
	s.logVPNHandshakes(observer.observe(samples, time.Unix(110, 0)))
	lines := strings.Split(logger.String(), "\n")
	if len(lines) != 65 {
		t.Fatal("unbounded logger writes", len(lines))
	}
	for i, line := range lines {
		for _, unit := range []string{"netosd.service", "other.service", ""} {
			row := map[string]json.RawMessage{}
			for key, value := range map[string]string{"_SYSTEMD_UNIT": unit, "SYSLOG_IDENTIFIER": "netosd.service", "MESSAGE": "2026/11/13 17:00:00 [инфо] " + line, "PRIORITY": "4"} {
				row[key], _ = json.Marshal(value)
			}
			e, keep := journalLogEntry(row, "vpn")
			if keep != (unit == "netosd.service") {
				t.Fatal("wrong source authority", unit, e)
			}
			if !keep {
				continue
			}
			if i < 64 && (e.Result != "success" || !strings.Contains(e.Server, "Server (server)") || !strings.Contains(e.Event, "начале наблюдения")) {
				t.Fatal(e)
			}
			if i == 64 && (e.Result != "warning" || !strings.Contains(e.Event, "6")) {
				t.Fatal(e)
			}
			all, allKeep := allJournalEntry(row, false)
			if !allKeep || all != e {
				t.Fatal("noncanonical General", all, e)
			}
			if _, kept := journalLogEntry(row, "services"); kept {
				t.Fatal("duplicate Services")
			}
			if _, kept := journalLogEntry(row, "access"); kept {
				t.Fatal("duplicate Access")
			}
		}
	}
	s.logVPNHandshakes(observer.observe(samples, time.Unix(111, 0)))
	if len(strings.Split(logger.String(), "\n")) != 65 {
		t.Fatal("unchanged observation wrote again")
	}
}

func TestHandshakePagesFindEventsBehindDaemonNoise(t *testing.T) {
	run := &pagedVPNRunner{}
	for i := 0; i < 900; i++ {
		message := "routine daemon info"
		if i >= 750 {
			message = `[инфо] netos-vpn-handshake-v1 {"observed":110,"handshake":100,"server":"server","peer":"peer","index":1,"protocol":"wireguard"}`
		}
		run.rows = append(run.rows, strings.Replace(vpnPageRow(i, message), "netos-ocserv-srv12.service", "netosd.service", 1))
	}
	s := &Server{StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 5; page++ {
		w := httptest.NewRecorder()
		s.handleJournalLogPage(w, httptest.NewRequest("GET", "/?kind=vpn&result=success&object=server&cursor="+url.QueryEscape(cursor), nil))
		var p journalLogPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal(w.Code, w.Body.String())
		}
		for _, e := range p.Entries {
			if seen[e.ID] || e.HandshakeTime == "" {
				t.Fatal("duplicate or missing handshake time", e)
			}
			seen[e.ID] = true
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 150 || cursor != "" || run.calls != 3 {
		t.Fatal("events lost behind noise", len(seen), run.calls)
	}
}

func TestHandshakeJournalRejectsInvalidRecordAndOldCursor(t *testing.T) {
	for _, raw := range []string{`{}`, `{"observed":1,"suppressed":-1}`, `{"observed":1,"suppressed":3,"peer":"forged"}`, `{"observed":1,"handshake":2,"server":"s","peer":"p","index":1,"protocol":"wireguard"}`} {
		e := logEntry{Message: "[инфо] " + vpnHandshakeMarker + raw}
		if vpnHandshakeLogFields(&e, "netosd.service") {
			t.Fatal("malformed accepted", raw)
		}
	}
	now := time.Now().UTC()
	for _, kind := range []string{"vpn", "all"} {
		old, _ := json.Marshal(journalLogCursor{Schema: 1, Kind: kind, Anchor: "old", From: now.Add(-time.Hour), To: now})
		q := "/?kind=" + kind + "&cursor=" + base64.RawURLEncoding.EncodeToString(old)
		if _, err := journalPageRequest(httptest.NewRequest("GET", q, nil), now); err == nil {
			t.Fatal("old source snapshot accepted", kind)
		}
	}
}
