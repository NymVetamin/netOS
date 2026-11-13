//go:build linux

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/system"
)

// Read-only journal comparison against the former independent selectors.
// The database and DNS fixture are isolated temporary files.
func TestIntegrationAllLogPages(t *testing.T) {
	if os.Getenv("NETOS_ALL_PAGE_INTEGRATION") != "1" {
		t.Skip("requires authorized Linux journal with service, VPN, DNS and SSH records")
	}
	from, err := time.Parse(time.RFC3339, os.Getenv("NETOS_GENERAL_FROM"))
	if err != nil {
		t.Fatal(err)
	}
	to, err := time.Parse(time.RFC3339, os.Getenv("NETOS_GENERAL_TO"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := &system.Exec{Timeout: time.Minute, MaxOutputBytes: 64 << 20}
	queries := []struct {
		kind string
		args []string
	}{
		{"dns", []string{"-u", "netos-unbound.service", "-u", "dnsmasq.service", "-u", "netos-dnsmasq.service", "-u", "netos-dnsproxy.service"}},
		{"services", serviceJournalMatches()},
		{"services", []string{"-u", "netosd.service", "--grep=\\[(пред|ошиб)\\]", "PRIORITY=5", "PRIORITY=6", "PRIORITY=7"}},
		{"vpn", []string{"-u", "netos-ocserv-srv*.service", "-u", "netos-strongswan.service", "-u", "netos-vpn-l2tp-srv*.service", "--grep=" + ocservEventPattern + "|" + ikeEventPattern + "|" + l2tpEventPattern}},
		{"access", []string{"-u", "ssh.service", "-u", "sshd.service", "--grep=" + sshEventPattern}},
		{"firewall", []string{"_TRANSPORT=kernel", "--grep=netos "}},
	}
	expected := map[string]map[string]logEntry{}
	for _, query := range queries {
		args := []string{"--no-pager", "--quiet", "-o", "json", "--since=" + journalPageTime(from), "--until=" + journalPageTime(to), "-n", "100000", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT,_PID,UNIT,MESSAGE_ID,PRIORITY,IKE_SA_NAME"}
		raw, err := baseline.Run(context.Background(), "journalctl", append(args, query.args...)...)
		if err != nil && !emptyJournalMatch(raw, err) {
			t.Fatal(err)
		}
		scan := bufio.NewScanner(strings.NewReader(raw))
		scan.Buffer(make([]byte, 4096), 2<<20)
		count := 0
		for scan.Scan() {
			count++
			var row map[string]json.RawMessage
			if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			entry, keep := journalLogEntry(row, query.kind)
			if !keep {
				continue
			}
			var id string
			_ = json.Unmarshal(row["__CURSOR"], &id)
			entry.ID = "journal:" + id
			if expected[entry.ID] == nil {
				expected[entry.ID] = map[string]logEntry{}
			}
			expected[entry.ID][entry.Source] = entry
		}
		if scan.Err() != nil || count >= 100000 {
			t.Fatal("baseline truncated", count, scan.Err())
		}
	}
	if len(expected) == 0 {
		t.Fatal("native journal fixture is empty")
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	commands := 0
	runner := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20, OnCommand: func(string, []string) { commands++ }}
	s := &Server{Store: st, StorageRunner: runner}
	seen := map[string]bool{}
	cursor := ""
	start := time.Now()
	for page := 0; page < 2000; page++ {
		query := "from=" + url.QueryEscape(from.Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339)) + "&cursor=" + url.QueryEscape(cursor)
		p, code := allPageRequest(t, s, filepath.Join(dir, "dns.log"), query)
		if code != 200 || p.Incomplete || len(p.Warnings) > 0 || len(p.Entries) > 100 || p.Scanned > 500 {
			t.Fatalf("page=%d code=%d warnings=%v", page, code, p.Warnings)
		}
		for _, entry := range p.Entries {
			if seen[entry.ID] || expected[entry.ID][entry.Source] != entry {
				t.Fatalf("duplicate, extra or altered event source=%s unit=%s", entry.Source, entry.Unit)
			}
			seen[entry.ID] = true
		}
		if p.Next == "" {
			if len(seen) != len(expected) {
				t.Fatalf("missing events: got=%d want=%d", len(seen), len(expected))
			}
			t.Logf("events=%d pages=%d commands=%d elapsed=%s", len(seen), page+1, commands, time.Since(start))
			return
		}
		if p.Next == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = p.Next
	}
	t.Fatal("page budget exhausted")
}
