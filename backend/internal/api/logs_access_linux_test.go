//go:build linux

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/netos-router/netos/internal/system"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationAccessLogs(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized test machine and SSH fixtures")
	}
	s, _, _ := newAuthedServer(t)
	s.StorageRunner = &system.Exec{Timeout: 10 * time.Second}
	for _, password := range []string{"initial-password-123", "wrong-log-test"} {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.handleLogin(w, req)
		expected := 200
		if password == "wrong-log-test" {
			expected = 401
		}
		if w.Code != expected {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	data := readAllJournalPages(t, s, "access")
	// Compare every SSH cursor with an independent, time-bounded journal read.
	// This larger output allowance belongs only to the integration test.
	reference := &system.Exec{Timeout: 30 * time.Second, MaxOutputBytes: 64 << 20}
	raw, err := reference.Run(context.Background(), "journalctl", "--no-pager", "--quiet", "-o", "json", "-u", "ssh.service", "-u", "sshd.service", "--since="+journalPageTime(data.From), "--until="+journalPageTime(data.CapturedAt), "-n", "100000", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER")
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	scan := bufio.NewScanner(strings.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 2<<20)
	count := 0
	for scan.Scan() {
		count++
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if _, keep := journalLogEntry(row, "access"); keep {
			var id string
			if err := json.Unmarshal(row["__CURSOR"], &id); err != nil {
				t.Fatal(err)
			}
			expected["journal:"+id] = true
		}
	}
	if scan.Err() != nil || count >= 100000 {
		t.Fatal("reference incomplete", count, scan.Err())
	}
	for _, e := range data.Entries {
		if e.Protocol != "ssh" {
			continue
		}
		if !expected[e.ID] {
			t.Fatal("unexpected SSH cursor", e.ID)
		}
		delete(expected, e.ID)
	}
	if len(expected) != 0 {
		t.Fatal("missing SSH cursors", len(expected))
	}
	t.Logf("all SSH cursors match independent journal read: raw=%d events=%d", count, len(data.Entries))
	found := map[string]bool{}
	for _, e := range data.Entries {
		if e.Protocol == "panel" && e.User == "admin" {
			found["panel-"+e.Result] = true
		}
		if e.Protocol == "ssh" && e.User == "root" && e.Result == "success" {
			found["ssh-success"] = true
		}
		if e.Protocol == "ssh" && e.User == "netos-log-invalid" && e.Result == "failure" {
			found["ssh-failure"] = true
		}
	}
	for _, key := range []string{"panel-success", "panel-failure", "ssh-success", "ssh-failure"} {
		if !found[key] {
			t.Error("missing event", key)
		}
	}
}
