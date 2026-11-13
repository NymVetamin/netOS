package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

type allPageRunner struct {
	accessLogRunner
	units, kernel accessPageRunner
}

func (r *allPageRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	for _, arg := range args {
		if arg == "_TRANSPORT=kernel" {
			return r.kernel.Run(ctx, name, args...)
		}
	}
	return r.units.Run(ctx, name, args...)
}

func allPageRequest(t *testing.T, s *Server, path, query string) (journalLogPage, int) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/logs?kind=all&"+query, nil)
	s.handleAllLogPage(w, r, path)
	var p journalLogPage
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log(w.Body.String())
	}
	return p, w.Code
}

func TestAllPagesFourSourcesSnapshot(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 130; i++ {
		if err := st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	runner := &allPageRunner{}
	at := time.Now().Add(-time.Minute)
	for i := 0; i < 701; i++ {
		message := "noise"
		if i > 500 {
			message = "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"
		}
		row, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("u", i), "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": message})
		runner.units.rows = append(runner.units.rows, string(row))
		if i < 150 {
			row, _ = json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("k", i), "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_TRANSPORT": "kernel", "MESSAGE": "netos INPUT fixture"})
			runner.kernel.rows = append(runner.kernel.rows, string(row))
		}
	}
	path := filepath.Join(dir, "dns.log")
	line := at.Format("2006/01/02 15:04:05.000000") + " query[A] same.example from 192.0.2.1\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(line, 160)), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, StorageRunner: runner}
	seen, counts := map[string]bool{}, map[string]int{}
	cursor := ""
	for n := 0; n < 30; n++ {
		p, status := allPageRequest(t, s, path, "cursor="+url.QueryEscape(cursor))
		if status != 200 || p.Incomplete || len(p.Warnings) != 0 || len(p.Entries) > 100 || p.Scanned > 500 {
			t.Fatalf("page %d status=%d %+v", n, status, p)
		}
		for _, e := range p.Entries {
			if e.ID == "" || seen[e.ID] {
				t.Fatalf("duplicate or absent identity %q", e.ID)
			}
			seen[e.ID] = true
			counts[e.Source+":"+e.Protocol]++
		}
		if n == 0 {
			if err := st.Audit(store.AuditEntry{Action: "login", User: "late", Success: true}); err != nil {
				t.Fatal(err)
			}
			for _, stream := range []*accessPageRunner{&runner.units, &runner.kernel} {
				var row map[string]string
				_ = json.Unmarshal([]byte(stream.rows[0]), &row)
				row["__CURSOR"] += "late"
				data, _ := json.Marshal(row)
				stream.rows = append([]string{string(data)}, stream.rows...)
			}
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString(line)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if p.Next == "" {
			if counts["access:panel"] != 130 || counts["access:ssh"] != 200 || counts["dns:"] != 160 || counts["firewall:"] != 150 {
				t.Fatal(counts)
			}
			return
		}
		if p.Next == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = p.Next
	}
	t.Fatal("page budget exhausted")
}

func TestAllJournalClassificationBoundaries(t *testing.T) {
	for _, tc := range []struct{ unit, transport, message, source string }{
		{"ssh.service", "stdout", "Failed password for alice from 192.0.2.1 port 42 ssh2", "access"},
		{"unrelated.service", "stdout", "Failed password for alice from 192.0.2.1 port 42 ssh2", ""},
		{"netos-unbound.service", "stdout", "info: 192.0.2.1 fixture.example. A IN", "dns"},
		{"unrelated.service", "stdout", "query[A] fixture.example from 192.0.2.1", ""},
		{"netos-ocserv-srv1.service", "stdout", "worker[alice]: 192.0.2.1 failed authentication for 'alice'", "vpn"},
		{"netos-unbound.service", "stdout", "resolver failed", "services"},
		{"ssh.service", "stdout", "unrecognized warning", ""},
		{"netosd.service", "kernel", "netos INPUT fixture", "firewall"},
	} {
		row := map[string]json.RawMessage{}
		for k, v := range map[string]string{"_SYSTEMD_UNIT": tc.unit, "_TRANSPORT": tc.transport, "MESSAGE": tc.message, "PRIORITY": "3"} {
			row[k], _ = json.Marshal(v)
		}
		entry, keep := allJournalEntry(row, tc.transport == "kernel")
		if keep != (tc.source != "") || entry.Source != tc.source {
			t.Fatalf("%+v -> %+v/%v", tc, entry, keep)
		}
		if keep {
			want, _ := journalLogEntry(row, tc.source)
			if entry != want {
				t.Fatalf("classification changed event fields: got=%+v want=%+v", entry, want)
			}
		}
		if tc.transport == "kernel" {
			if _, keep := allJournalEntry(row, false); keep {
				t.Fatal("kernel duplicated in unit stream")
			}
		}
	}
}

func TestAllPagesRetryAndCursorErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &allPageRunner{}
	for i := 0; i < 250; i++ {
		row, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("kernel", i), "__REALTIME_TIMESTAMP": fmt.Sprint(time.Now().Add(-time.Minute).UnixMicro()), "_TRANSPORT": "kernel", "MESSAGE": "netos INPUT fixture"})
		runner.kernel.rows = append(runner.kernel.rows, string(row))
	}
	s := &Server{Store: st, StorageRunner: runner}
	path := filepath.Join(dir, "dns.log")
	first, code := allPageRequest(t, s, path, "")
	if code != 200 || len(first.Entries) != 100 || first.Next == "" {
		t.Fatal(code, first)
	}
	query := "cursor=" + url.QueryEscape(first.Next)
	second, code := allPageRequest(t, s, path, query)
	if code != 200 || len(second.Entries) != 100 {
		t.Fatal(code, second)
	}
	runner.kernel.fail = true
	partial, code := allPageRequest(t, s, path, query)
	if code != 200 || !partial.Incomplete || partial.Next != "" || len(partial.Warnings) != 1 {
		t.Fatal(code, partial)
	}
	runner.kernel.fail = false
	retry, code := allPageRequest(t, s, path, query)
	if code != 200 || !reflect.DeepEqual(second, retry) {
		t.Fatal("retry changed snapshot", code, second, retry)
	}
	if _, code := allPageRequest(t, s, path, query+"&object=changed"); code != 400 {
		t.Fatal("changed filters accepted", code)
	}
	// The consumed anchor is the hundredth record, independent of wall-clock
	// ordering. Losing it must produce refresh-required, not a false EOF.
	runner.kernel.rows = append(runner.kernel.rows[:99], runner.kernel.rows[100:]...)
	if _, code := allPageRequest(t, s, path, query); code != 409 {
		t.Fatal("missing anchor accepted", code)
	}
}

func TestAllPagesSourcesFailIndependently(t *testing.T) {
	for _, failed := range []string{"units", "kernel", "audit", "file"} {
		t.Run(failed, func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.Open(filepath.Join(dir, "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
				t.Fatal(err)
			}
			runner := &allPageRunner{}
			at := time.Now().Add(-time.Minute)
			unit, _ := json.Marshal(map[string]string{"__CURSOR": "unit", "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"})
			kernel, _ := json.Marshal(map[string]string{"__CURSOR": "kernel", "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_TRANSPORT": "kernel", "MESSAGE": "netos INPUT fixture"})
			runner.units.rows = []string{string(unit)}
			runner.kernel.rows = []string{string(kernel)}
			path := filepath.Join(dir, "dns.log")
			if failed == "file" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(at.Format("2006/01/02 15:04:05.000000")+" query[A] fixture.example from 192.0.2.1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			s := &Server{Store: st, StorageRunner: runner}
			switch failed {
			case "units":
				runner.units.fail = true
			case "kernel":
				runner.kernel.fail = true
			case "audit":
				s.Store = nil
			}
			p, code := allPageRequest(t, s, path, "")
			if code != 200 || !p.Incomplete || p.Next != "" || len(p.Warnings) != 1 || len(p.Entries) != 3 {
				t.Fatal(code, p)
			}
		})
	}
}

func TestAllJournalManagerTargets(t *testing.T) {
	for _, target := range []string{"netos-unbound.service", "ssh.service", "unrelated.service"} {
		row := map[string]json.RawMessage{}
		for key, value := range map[string]string{"_SYSTEMD_UNIT": "init.scope", "_PID": "1", "UNIT": target, "PRIORITY": "6", "MESSAGE_ID": "39f53479d3a045ac8e11786248231fbf", "MESSAGE": "localized manager message"} {
			row[key], _ = json.Marshal(value)
		}
		e, keep := allJournalEntry(row, false)
		if keep != strings.HasPrefix(target, "netos") || keep && (e.Unit != target || e.Source != "services" || e.Event == "") {
			t.Fatalf("target=%s event=%+v keep=%v", target, e, keep)
		}
	}
}

func BenchmarkAllLogPage(b *testing.B) {
	for _, size := range []int{30, 3000, 300000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			dir := b.TempDir()
			st, err := store.Open(filepath.Join(dir, "audit.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			at := time.Now().Add(-time.Minute)
			line := at.Format("2006/01/02 15:04:05.000000") + " query[A] benchmark.invalid from 192.0.2.1\n"
			path := filepath.Join(dir, "dns.log")
			if err := os.WriteFile(path, []byte(strings.Repeat(line, size)), 0600); err != nil {
				b.Fatal(err)
			}
			runner := &allPageRunner{}
			// The fixture simulates the bounded raw journal batches; it does
			// not measure process spawn or journal index lookup (native test).
			for i := 0; i < min(size, 3000); i++ {
				row, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("u", i), "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"})
				runner.units.rows = append(runner.units.rows, string(row))
				row, _ = json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("k", i), "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_TRANSPORT": "kernel", "MESSAGE": "netos INPUT fixture"})
				runner.kernel.rows = append(runner.kernel.rows, string(row))
			}
			s := &Server{Store: st, StorageRunner: runner}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleAllLogPage(w, httptest.NewRequest("GET", "/api/logs?kind=all", nil), path)
				if w.Code != 200 {
					b.Fatal(w.Body.String())
				}
			}
		})
	}
}

func TestAllPagesFileBudgetFilterAndRotation(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	at := time.Now().Add(-time.Minute)
	stamp := at.Format("2006/01/02 15:04:05.000000")
	path := filepath.Join(dir, "dns.log")
	text := stamp + " query[A] target.invalid from 192.0.2.1\n" + strings.Repeat(stamp+" "+strings.Repeat("x", 10000)+"\n", 150)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &allPageRunner{}
	row, _ := json.Marshal(map[string]string{"__CURSOR": "older", "__REALTIME_TIMESTAMP": fmt.Sprint(at.Add(-time.Minute).UnixMicro()), "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"})
	runner.units.rows = []string{string(row)}
	s := &Server{Store: st, StorageRunner: runner}
	cursor := ""
	var sources []string
	for page := 0; page < 10; page++ {
		p, code := allPageRequest(t, s, path, "cursor="+url.QueryEscape(cursor))
		if code != 200 || p.Incomplete {
			t.Fatal(code, p)
		}
		for _, e := range p.Entries {
			sources = append(sources, strings.SplitN(e.ID, ":", 2)[0])
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if cursor != "" || strings.Join(sources, ",") != "file,journal" {
		t.Fatal("byte barrier lost order", sources)
	}
	text = stamp + " query[A] target.invalid from 192.0.2.1\n" + strings.Repeat(stamp+" query[A] other.invalid from 192.0.2.1\n", 700)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	runner.units.rows = nil
	p, code := allPageRequest(t, s, path, "object=target.invalid")
	if code != 200 || len(p.Entries) != 0 || p.Scanned != 500 || p.Next == "" {
		t.Fatal(code, p)
	}
	query := "object=target.invalid&cursor=" + url.QueryEscape(p.Next)
	next, code := allPageRequest(t, s, path, query)
	if code != 200 || len(next.Entries) != 1 || next.Next != "" {
		t.Fatal(code, next)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := allPageRequest(t, s, path, query); code != 409 {
		t.Fatal("rotation hidden", code)
	}
}

func TestAllPagesAuditPruneAndCancellation(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 130; i++ {
		if err := st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Store: st, StorageRunner: &allPageRunner{}}
	path := filepath.Join(dir, "dns.log")
	p, code := allPageRequest(t, s, path, "")
	if code != 200 || p.Next == "" || len(p.Entries) != 100 {
		t.Fatal(code, p)
	}
	if err := st.PruneAudit(1); err != nil {
		t.Fatal(err)
	}
	if _, code := allPageRequest(t, s, path, "cursor="+url.QueryEscape(p.Next)); code != 409 {
		t.Fatal("prune hidden", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/api/logs?kind=all", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	s.handleAllLogPage(w, r, path)
	var partial journalLogPage
	if err := json.Unmarshal(w.Body.Bytes(), &partial); err != nil || w.Code != 200 || !partial.Incomplete || partial.Next != "" {
		t.Fatal(w.Code, w.Body.String(), err)
	}
}
