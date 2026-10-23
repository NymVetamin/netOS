package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogTimestampAndBoundedFile(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.FixedZone("fixture", 3*3600))
	if got := dnsLineTime("Dec 31 23:59:59 dnsmasq query", now); got != "2025-12-31T20:59:59Z" {
		t.Fatal(got)
	}
	if got := dnsLineTime("2026/01/01 10:00:00.123456 query", now); got != "2026-01-01T07:00:00.123456Z" {
		t.Fatal(got)
	}
	if dnsLineTime("unknown timestamp", now) != "" {
		t.Fatal("invented timestamp")
	}
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 300000)+"\n"+strings.Repeat("Jan  1 11:00:00 dnsmasq[1]: query[A] fixture.example from 192.0.2.1\n", 500)), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := readDNSLog(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > 300 || len(rows) == 0 || strings.Contains(rows[0].Message, "xxxx") {
		t.Fatal("unbounded or partial record returned")
	}
}
func TestJournalParsingAndInvalidData(t *testing.T) {
	raw := `{"__REALTIME_TIMESTAMP":"1000000","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.0.2.1 fixture.example. A IN"}`
	rows, err := parseJournalEntries(raw, "dns")
	if err != nil || len(rows) != 1 || rows[0].Source != "dns" || rows[0].Time != "1970-01-01T00:00:01Z" {
		t.Fatal(rows, err)
	}
	rows, err = parseJournalEntries(raw, "firewall")
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	if _, err = parseJournalEntries("not-json", "dns"); err == nil {
		t.Fatal("bad journal ignored")
	}
}

type logRunner struct{ calls []string }

type orderedDNSRunner struct{ logRunner }

func (r *orderedDNSRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return `{"__REALTIME_TIMESTAMP":"1792486481000000","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 127.0.0.1 old.example. A IN"}` + "\n" +
		`{"_SYSTEMD_UNIT":"netos-dnsmasq.service","MESSAGE":"query[A] unknown-time.example from 127.0.0.1"}` + "\n" +
		`{"__REALTIME_TIMESTAMP":"1792760305000000","_SYSTEMD_UNIT":"netos-dnsmasq.service","MESSAGE":"query[A] current.example from 127.0.0.1"}`, nil
}

func TestDNSLogsShowCurrentResolverBeforeOldProvider(t *testing.T) {
	for _, kind := range []string{"dns", "all"} {
		t.Run(kind, func(t *testing.T) {
			s := &Server{StorageRunner: &orderedDNSRunner{}}
			req := httptest.NewRequest("GET", "/api/logs?kind="+kind, nil)
			req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
			w := httptest.NewRecorder()
			s.handleLogs(w, req)
			var data struct{ Entries []logEntry }
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || w.Code != 200 {
				t.Fatalf("response: %d %v", w.Code, err)
			}
			var rows []logEntry
			for _, e := range data.Entries {
				if strings.Contains(e.Message, ".example") {
					rows = append(rows, e)
				}
			}
			if len(rows) != 3 {
				t.Fatalf("lost or duplicated records: %+v", rows)
			}
			first, second := "current.example", "old.example"
			if kind == "all" {
				first, second = second, first
			}
			if !strings.Contains(rows[0].Message, first) || !strings.Contains(rows[1].Message, second) || rows[2].Time != "" {
				t.Fatalf("unexpected %s order: %+v", kind, rows)
			}
		})
	}
}

func (r *logRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if name != "journalctl" {
		return "", fmt.Errorf("unexpected command")
	}
	if strings.Contains(cmd, "--grep") {
		return "", fmt.Errorf("kernel unavailable")
	}
	if strings.Contains(cmd, "netos-unbound.service") {
		return `{"__REALTIME_TIMESTAMP":"3000000","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.0.2.1 fixture.example. A IN"}`, nil
	}
	return `{"__REALTIME_TIMESTAMP":"2000000","_SYSTEMD_UNIT":"netosd.service","MESSAGE":"fixture started"}`, nil
}
func (r *logRunner) RunInput(_ context.Context, _ string, _ string, _ ...string) (string, error) {
	return "", fmt.Errorf("unexpected write")
}
func TestLogsAuthorizationSourcesAndPartialErrors(t *testing.T) {
	runner := &logRunner{}
	s := &Server{StorageRunner: runner}
	req := httptest.NewRequest("GET", "/api/logs?kind=all", nil)
	w := httptest.NewRecorder()
	s.handleLogs(w, req)
	if w.Code != 403 || len(runner.calls) != 0 {
		t.Fatal("unauthorized log read")
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxRole, "admin"))
	w = httptest.NewRecorder()
	s.handleLogs(w, req)
	var data struct {
		Entries  []logEntry
		Warnings []string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(data.Entries) == 0 || !strings.Contains(strings.Join(data.Warnings, " "), "kernel unavailable") || len(runner.calls) != 3 {
		t.Fatal(w.Body.String(), runner.calls)
	}
	if len(data.Entries) >= 2 && data.Entries[0].Time != "1970-01-01T00:00:02Z" {
		t.Fatal("merged entries not chronological", data.Entries)
	}
	bad := httptest.NewRequest("GET", "/api/logs?kind=/etc/passwd", nil)
	bad = bad.WithContext(req.Context())
	w = httptest.NewRecorder()
	s.handleLogs(w, bad)
	if w.Code != 400 || len(runner.calls) != 3 {
		t.Fatal("unvalidated source")
	}
}

type journalNoMatch struct{}

func (journalNoMatch) Error() string { return "exit status 1" }
func (journalNoMatch) ExitCode() int { return 1 }
func TestEmptyFirewallJournalIsNotReadFailure(t *testing.T) {
	if !emptyJournalMatch("", fmt.Errorf("journalctl: %w: ", journalNoMatch{})) {
		t.Fatal("empty match treated as failure")
	}
	if emptyJournalMatch("", fmt.Errorf("journalctl: %w: permission denied", journalNoMatch{})) {
		t.Fatal("read error masked")
	}
}

func TestDNSQueryFiltering(t *testing.T) {
	for _, message := range []string{
		"dnsmasq[1]: query[A] example.org from 192.0.2.10",
		"[1791969615] unbound[1:0] info: 192.0.2.10 example.org. AAAA IN",
		"unbound[1:0] query: 2001:db8::1 example.org. TYPE65 IN",
		`time=2026-10-16T00:00:00Z level=DEBUG msg=in prefix=proxy line_num=7 line=";example.org.\tIN\t A"`,
		"[debug] in: ;example.org. IN A",
	} {
		if !isDNSQuery(message) {
			t.Errorf("query lost: %s", message)
		}
	}
	for _, message := range []string{
		"Started netos-unbound.service", "info: start of service (unbound 1.26.1).", "info: service stopped (unbound 1.26.1).",
		"dnsmasq[1]: read /etc/hosts - 4 names", "dnsmasq[1]: reply example.org is 192.0.2.2",
		"info: 192.0.2.10 example.org. A IN NOERROR 0.01 1 100", "info: not-an-ip example.org A IN",
		`level=DEBUG msg=out line_num=7 line=";example.org.\tIN\t A"`, "query logging enabled",
	} {
		if isDNSQuery(message) {
			t.Errorf("service/reply misclassified: %s", message)
		}
	}
	raw := `{"_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: start of service (unbound 1.26.1)."}` + "\n" + `{"_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.0.2.1 example.org. A IN"}`
	for _, source := range []string{"dns", "services"} {
		rows, err := parseJournalEntries(raw, source)
		if err != nil || len(rows) != 1 || rows[0].Source != source {
			t.Fatal(source, rows, err)
		}
		if (source == "dns") != isDNSQuery(rows[0].Message) {
			t.Fatal(source, rows)
		}
	}
	path := filepath.Join(t.TempDir(), "dns.log")
	os.WriteFile(path, []byte("started dnsmasq\nquery[A] example.org from 192.0.2.1\nreply example.org is 192.0.2.2\n"), 0600)
	rows, err := readDNSLog(path, time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}
