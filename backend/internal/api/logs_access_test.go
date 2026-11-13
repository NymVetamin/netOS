package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogsExposePanelAccess(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	s.StorageRunner = &orderedDNSRunner{}
	if err := s.Store.Audit(store.AuditEntry{User: "admin", Action: "login", SourceIP: "192.0.2.2", Success: true}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/logs?kind=access", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
	w := httptest.NewRecorder()
	s.handleLogs(w, req)
	var data struct{ Entries []logEntry }
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || w.Code != 200 || len(data.Entries) == 0 {
		t.Fatalf("access unavailable: %d %s %v", w.Code, w.Body.String(), err)
	}
	if len(data.Entries) != 1 || data.Entries[0].User != "admin" || data.Entries[0].Address != "192.0.2.2" || data.Entries[0].Protocol != "panel" || data.Entries[0].Result != "success" {
		t.Fatal(data.Entries)
	}
}

type accessLogRunner struct {
	raw  string
	fail bool
}

func (r accessLogRunner) Run(context.Context, string, ...string) (string, error) {
	if r.fail {
		return "", fmt.Errorf("SSH journal unavailable")
	}
	return r.raw, nil
}
func (r accessLogRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", fmt.Errorf("unexpected write")
}

func TestAccessSourcesFailIndependently(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	if err := s.Store.Audit(store.AuditEntry{Action: "login", User: "admin", Success: true}); err != nil {
		t.Fatal(err)
	}
	s.StorageRunner = accessLogRunner{fail: true}
	read := func() struct {
		Entries  []logEntry
		Warnings []string
	} {
		req := httptest.NewRequest("GET", "/api/logs?kind=access", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, req)
		var result struct {
			Entries  []logEntry
			Warnings []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
			t.Fatal(err, w.Code)
		}
		return result
	}
	r := read()
	if len(r.Entries) != 1 || r.Entries[0].Protocol != "panel" || len(r.Warnings) != 1 {
		t.Fatal(r)
	}
	s.StorageRunner = accessLogRunner{raw: accessPageRow("fixture", "Accepted publickey for alice from 192.0.2.1 port 42 ssh2")}
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	r = read()
	if len(r.Entries) != 1 || r.Entries[0].Protocol != "ssh" || len(r.Warnings) != 1 {
		t.Fatal(r)
	}
}

func BenchmarkAccessLogHandler(b *testing.B) {
	for _, n := range []int{30, 3000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			st, err := store.Open(filepath.Join(b.TempDir(), "audit.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			for i := 0; i < n; i++ {
				if err = st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
					b.Fatal(err)
				}
			}
			run := &accessPageRunner{}
			for i := 0; i < n; i++ {
				run.rows = append(run.rows, accessPageRow(fmt.Sprint("j", i), "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"))
			}
			s := &Server{Store: st, StorageRunner: run}
			req := httptest.NewRequest("GET", "/api/logs?kind=access", nil)
			req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleLogs(w, req)
				if w.Code != 200 || strings.Contains(w.Body.String(), `"incomplete":true`) {
					b.Fatal(w.Code)
				}
			}
		})
	}
}

func TestSSHAccessEvents(t *testing.T) {
	for _, tt := range []struct{ message, user, address, result string }{
		{"Accepted publickey for alice from 192.0.2.1 port 2345 ssh2: ED25519 SHA256:test", "alice", "192.0.2.1", "success"},
		{"Failed password for invalid user bob from 2001:db8::1 port 42 ssh2", "bob", "2001:db8::1", "failure"},
		{"Invalid user bob from 192.0.2.1 port 42", "bob", "192.0.2.1", "failure"},
		{"pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)", "alice", "", "success"},
		{"pam_unix(sshd:session): session closed for user alice", "alice", "", "success"},
		{"Disconnected from user alice 192.0.2.1 port 42", "alice", "192.0.2.1", "info"},
		{"Connection closed by authenticating user alice 2001:db8::1 port 42 [preauth]", "alice", "2001:db8::1", "info"},
		{"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1  user=bob", "bob", "192.0.2.1", "failure"},
		{"Accepted unknown-format", "", "", "info"},
	} {
		raw, _ := json.Marshal(map[string]string{"MESSAGE": tt.message, "_SYSTEMD_UNIT": "ssh.service"})
		rows, err := parseJournalEntries(string(raw), "access")
		if err != nil || len(rows) != 1 {
			t.Fatal(tt.message, rows, err)
		}
		e := rows[0]
		if e.User != tt.user || e.Address != tt.address || e.Result != tt.result || e.Message != tt.message {
			t.Fatalf("%s: %+v", tt.message, e)
		}
	}
	rows, err := parseJournalEntries(`{"MESSAGE":"Server listening on 0.0.0.0 port 22"}`, "access")
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
}
