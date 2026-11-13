package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEarlyLoginEventsPreserveResponsesAndSecrets(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	logger := &lifecycleLogger{}
	s.Logger = logger
	for i, tc := range []struct {
		reason, body string
		status       int
	}{
		{"request", `{"username":"admin",`, 400},
		{"request", `{"username":"admin","password":"secret"` + strings.Repeat(" ", maxLoginBodyBytes) + `}`, 400},
		{"credentials", `{"username":"","password":"secret"}`, 401},
		{"credentials", `{"username":"admin","password":"` + strings.Repeat("x", maxPasswordBytes+1) + `"}`, 401},
		{"blocked", `{"username":"admin","password":"secret"}`, 429},
		{"busy", `{"username":"admin","password":"secret"}`, 429},
	} {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		if tc.reason == "blocked" {
			s.loginFails[ip] = &failCounter{count: 6, last: time.Now(), until: time.Now().Add(time.Minute)}
		}
		if tc.reason == "busy" {
			for n := 0; n < maxConcurrentLogins; n++ {
				s.loginSlots <- struct{}{}
			}
		}
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(tc.body))
		r.RemoteAddr = ip + ":40000"
		r.Header.Set("X-Forwarded-For", "198.51.100.1")
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		if tc.reason == "busy" {
			for n := 0; n < maxConcurrentLogins; n++ {
				<-s.loginSlots
			}
		}
		if w.Code != tc.status {
			t.Fatal(tc.reason, w.Code)
		}
		line := logger.lines[len(logger.lines)-1]
		if strings.Contains(line, "secret") || strings.Contains(line, "password") || strings.Contains(line, "198.51.100.1") {
			t.Fatal("unsafe event", line)
		}
		entry := logEntry{Unit: "netosd.service", Message: "2026/11/13 12:34:56 [инфо] " + line}
		if !panelJournalFields(&entry) || entry.Address != ip || entry.Protocol != "panel" || entry.Result != "failure" {
			t.Fatal(entry)
		}
		if (tc.reason == "request" || tc.reason == "blocked") && entry.User != "" {
			t.Fatal("invented username", entry)
		}
		row := map[string]json.RawMessage{}
		for k, v := range map[string]string{"_SYSTEMD_UNIT": "netosd.service", "MESSAGE": entry.Message, "PRIORITY": "6"} {
			row[k], _ = json.Marshal(v)
		}
		access, ok := journalLogEntry(row, "access")
		all, allOK := allJournalEntry(row, false)
		if !ok || !allOK || access != all || access.Source != "access" {
			t.Fatal(access, all)
		}
		if _, keep := journalLogEntry(row, "services"); keep {
			t.Fatal("access noise leaked into services")
		}
		row["PRIORITY"] = json.RawMessage(`"3"`)
		if _, keep := journalLogEntry(row, "services"); keep {
			t.Fatal("stderr priority reclassified access as service error")
		}
	}
	rows, err := s.Store.ListAccessAudit(context.Background(), 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("early path wrote SQL", rows, err)
	}
	if len(logger.lines) != 6 {
		t.Fatal(len(logger.lines))
	}
}

func TestEarlyLoginAuditConcurrentBudgetAndWindow(t *testing.T) {
	logger := &lifecycleLogger{}
	s := &Server{Logger: logger}
	var wg sync.WaitGroup
	for n := 0; n < 1000; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.logPanelLogin("request", "", "192.0.2.1") }()
	}
	wg.Wait()
	if len(logger.lines) != earlyLoginLimit+1 {
		t.Fatal(len(logger.lines))
	}
	notices := 0
	for _, line := range logger.lines {
		e := logEntry{Unit: "netosd.service", Message: "[инфо] " + line}
		if !panelJournalFields(&e) {
			t.Fatal(line)
		}
		if e.Result == "info" {
			notices++
			if e.User != "" || e.Address != "" || e.Severity != "warning" {
				t.Fatal(e)
			}
		}
	}
	if notices != 1 {
		t.Fatal(notices)
	}
	gate := earlyLoginAudit{}
	now := time.Now()
	for n := 0; n < 10000; n++ {
		detail, notice, _ := gate.take(now)
		if detail != (n < earlyLoginLimit) || notice != (n == earlyLoginLimit) {
			t.Fatal(n, detail, notice)
		}
	}
	if detail, notice, _ := gate.take(now.Add(-time.Millisecond)); detail || notice {
		t.Fatal("late caller reopened budget")
	}
	if detail, notice, _ := gate.take(now.Add(time.Minute)); !detail || notice {
		t.Fatal("window did not reset")
	}
}

func TestPanelJournalRejectsUntrustedAndMalformedRecords(t *testing.T) {
	valid := `[инфо] netos-panel-access-v1 {"reason":"busy","user":"alice","address":"192.0.2.1"}`
	row := map[string]json.RawMessage{}
	row["SYSLOG_IDENTIFIER"], _ = json.Marshal("netosd.service")
	row["MESSAGE"], _ = json.Marshal(valid)
	if _, keep := journalLogEntry(row, "access"); keep {
		t.Fatal("untrusted syslog identifier impersonated netosd")
	}
	for _, tc := range []struct{ unit, message string }{
		{"ssh.service", valid}, {"netosd.service", "arbitrary " + valid},
		{"netosd.service", strings.Replace(valid, "busy", "unknown", 1)},
		{"netosd.service", valid + " trailing"},
		{"netosd.service", `[инфо] netos-panel-access-v1 {"reason":"limited","until":"invalid"}`},
		{"netosd.service", strings.Replace(valid, "alice", strings.Repeat("x", 65), 1)},
	} {
		e := logEntry{Unit: tc.unit, Message: tc.message}
		if panelJournalFields(&e) {
			t.Fatal(tc)
		}
	}
	logger := &lifecycleLogger{}
	s := &Server{Logger: logger}
	s.logPanelLogin("busy", "alice\n\"injected", "192.0.2.1")
	if strings.Contains(logger.lines[0], "\n") {
		t.Fatal("log injection")
	}
	e := logEntry{Unit: "netosd.service", Message: "[инфо] " + logger.lines[0]}
	if !panelJournalFields(&e) || e.User != "alice\n\"injected" {
		t.Fatal(e)
	}
}

func TestGeneralFindsPanelAuditLimitWarning(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	message := `[инфо] netos-panel-access-v1 {"reason":"limited","until":"2026-11-13T12:35:56Z"}`
	row, _ := json.Marshal(map[string]string{"__CURSOR": "notice", "__REALTIME_TIMESTAMP": fmt.Sprint(time.Now().Add(-time.Minute).UnixMicro()), "_SYSTEMD_UNIT": "netosd.service", "MESSAGE": message, "PRIORITY": "6"})
	s.StorageRunner = &allPageRunner{units: accessPageRunner{rows: []string{string(row)}}}
	for _, result := range []string{"info", "warning"} {
		p, code := allPageRequest(t, s, t.TempDir()+"/dns.log", "result="+result)
		if code != 200 || p.Incomplete || len(p.Entries) != 1 || p.Entries[0].Severity != "warning" {
			t.Fatal(result, code, p)
		}
	}
}

type earlyAuditBenchmarkLogger struct {
	writer *log.Logger
	calls  int
}

func (l *earlyAuditBenchmarkLogger) Infof(f string, args ...any) {
	l.calls++
	l.writer.Printf("[инфо] "+f, args...)
}
func (l *earlyAuditBenchmarkLogger) Warnf(string, ...any)  {}
func (l *earlyAuditBenchmarkLogger) Errorf(string, ...any) {}

func BenchmarkEarlyLoginHTTP(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("requests%d/audit%v", n, enabled), func(b *testing.B) {
				logger := &earlyAuditBenchmarkLogger{writer: log.New(io.Discard, "", log.LstdFlags)}
				s := &Server{loginFails: map[string]*failCounter{}}
				if enabled {
					s.Logger = logger
				}
				b.ReportAllocs()
				b.ResetTimer()
				for repeat := 0; repeat < b.N; repeat++ {
					s.loginAudit = earlyLoginAudit{}
					logger.calls = 0
					for i := 0; i < n; i++ {
						r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":`))
						r.RemoteAddr = "192.0.2.1:40000"
						w := httptest.NewRecorder()
						s.handleLogin(w, r)
						if w.Code != 400 {
							b.Fatal(w.Code)
						}
					}
					want := 0
					if enabled {
						want = earlyLoginLimit + 1
					}
					if logger.calls != want {
						b.Fatal(logger.calls, want)
					}
				}
			})
		}
	}
}
