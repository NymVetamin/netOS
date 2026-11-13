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
	"strconv"
	"strings"
	"testing"
	"time"
)

func dnsPageRequest(t *testing.T, s *Server, path, cursor string) (journalLogPage, int) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/logs?kind=dns&cursor="+url.QueryEscape(cursor), nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
	w := httptest.NewRecorder()
	s.handleDNSLogPage(w, r, path)
	var p journalLogPage
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
	}
	return p, w.Code
}

func TestDNSPagesMergeSnapshotAndNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	stamp := time.Now().Add(-time.Minute).Format("2006/01/02 15:04:05.000000")
	var content strings.Builder
	for i := 0; i < 1000; i++ {
		msg := "routine noise"
		if i%4 == 0 {
			msg = fmt.Sprintf("dnsmasq[1]: query[A] file%d.invalid from 192.0.2.1", i)
		}
		fmt.Fprintln(&content, stamp+" "+msg)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}
	run := &accessPageRunner{}
	for i := 0; i < 650; i++ {
		msg := "routine noise"
		if i%5 == 0 {
			msg = fmt.Sprintf("info: 192.0.2.1 journal%d.invalid. A IN", i)
		}
		row, _ := json.Marshal(map[string]string{"__CURSOR": fmt.Sprint("j", i), "__REALTIME_TIMESTAMP": strconv.FormatInt(time.Now().Add(-30*time.Second).UnixMicro(), 10), "_SYSTEMD_UNIT": "netos-unbound.service", "MESSAGE": msg})
		run.rows = append(run.rows, string(row))
	}
	s := &Server{StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	total := 0
	for page := 0; page < 30; page++ {
		p, status := dnsPageRequest(t, s, path, cursor)
		if status != 200 || p.Incomplete || p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal(status, p)
		}
		for _, e := range p.Entries {
			if seen[e.ID] || strings.Contains(e.Message, "injected") {
				t.Fatal("snapshot duplicate/new record", e)
			}
			seen[e.ID] = true
			total++
		}
		if page == 0 {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString(stamp + " dnsmasq[1]: query[A] injected.invalid from 192.0.2.1\n")
			f.Close()
			run.rows = append([]string{strings.Replace(run.rows[0], "j0", "injected", 1)}, run.rows...)
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if cursor != "" || total != 380 {
		t.Fatal("missing events", total, cursor)
	}
}

func TestDNSPageByteBudgetAndPartialRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	stamp := time.Now().Add(-time.Minute).Format("2006/01/02 15:04:05.000000")
	text := stamp + " dnsmasq[1]: query[A] oldest.invalid from 192.0.2.1\n" + strings.Repeat(stamp+" "+strings.Repeat("x", 10000)+"\n", 150)
	os.WriteFile(path, []byte(text), 0600)
	run := &accessPageRunner{accessLogRunner: accessLogRunner{fail: true}}
	journalRow, _ := json.Marshal(map[string]string{"__CURSOR": "j0", "__REALTIME_TIMESTAMP": strconv.FormatInt(time.Now().Add(-2*time.Minute).UnixMicro(), 10), "_SYSTEMD_UNIT": "netos-unbound.service", "MESSAGE": "info: 192.0.2.1 journal.invalid. A IN"})
	run.rows = []string{string(journalRow)}
	s := &Server{StorageRunner: run}
	p, status := dnsPageRequest(t, s, path, "")
	if status != 200 || !p.Incomplete || p.Next != "" {
		t.Fatal(status, p)
	}
	run.fail = false
	cursor := ""
	total, pages := 0, 0
	var sources []string
	for ; pages < 10; pages++ {
		p, status = dnsPageRequest(t, s, path, cursor)
		if status != 200 || p.Incomplete {
			t.Fatal(status, p)
		}
		total += len(p.Entries)
		for _, entry := range p.Entries {
			sources = append(sources, strings.SplitN(entry.ID, ":", 2)[0])
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if total != 2 || pages < 2 || cursor != "" || strings.Join(sources, ",") != "file,journal" {
		t.Fatal(total, pages)
	}
}

func TestDNSPageFilterBeforeLimitAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	stamp := time.Now().Add(-time.Minute).Format("2006/01/02 15:04:05.000000")
	os.WriteFile(path, []byte(stamp+" dnsmasq[1]: query[A] target.invalid from 192.0.2.1\n"+strings.Repeat(stamp+" dnsmasq[1]: query[A] other.invalid from 192.0.2.1\n", 700)), 0600)
	s := &Server{StorageRunner: &accessPageRunner{}}
	request := func(cursor, object string) (journalLogPage, int) {
		r := httptest.NewRequest("GET", "/api/logs?kind=dns&object="+object+"&cursor="+url.QueryEscape(cursor), nil)
		w := httptest.NewRecorder()
		s.handleDNSLogPage(w, r, path)
		var p journalLogPage
		if w.Code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
		}
		return p, w.Code
	}
	p, status := request("", "target.invalid")
	if status != 200 || len(p.Entries) != 0 || p.Next == "" || p.Scanned != 500 {
		t.Fatal(status, p)
	}
	next, status := request(p.Next, "target.invalid")
	if status != 200 || len(next.Entries) != 1 || next.Next != "" {
		t.Fatal(status, next)
	}
	if _, status = request(p.Next, "changed"); status != 400 {
		t.Fatal("filter changed", status)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("replacement\n"), 0600)
	if _, status = request(p.Next, "target.invalid"); status != 409 {
		t.Fatal("rotation hidden", status)
	}
}

func TestDNSPartialSourcesAndContinuationRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	os.Mkdir(path, 0700)
	raw, _ := json.Marshal(map[string]string{"__CURSOR": "j0", "__REALTIME_TIMESTAMP": strconv.FormatInt(time.Now().Add(-2*time.Minute).UnixMicro(), 10), "_SYSTEMD_UNIT": "netos-unbound.service", "MESSAGE": "info: 192.0.2.1 journal.invalid. A IN"})
	run := &accessPageRunner{rows: []string{string(raw)}}
	s := &Server{StorageRunner: run}
	p, status := dnsPageRequest(t, s, path, "")
	if status != 200 || !p.Incomplete || p.Next != "" || len(p.Entries) != 1 {
		t.Fatal("working journal lost on file error", status, p)
	}
	os.Remove(path)
	stamp := time.Now().Add(-time.Minute).Format("2006/01/02 15:04:05.000000")
	os.WriteFile(path, []byte(strings.Repeat(stamp+" dnsmasq[1]: query[A] file.invalid from 192.0.2.1\n", 350)), 0600)
	p, status = dnsPageRequest(t, s, path, "")
	if status != 200 || p.Incomplete || p.Next == "" || len(p.Entries) != 100 {
		t.Fatal(status, p)
	}
	run.fail = true
	preview, status := dnsPageRequest(t, s, path, p.Next)
	if status != 200 || !preview.Incomplete || preview.Next != "" || len(preview.Entries) != 100 {
		t.Fatal(status, preview)
	}
	run.fail = false
	retry, status := dnsPageRequest(t, s, path, p.Next)
	if status != 200 || retry.Incomplete || !reflect.DeepEqual(preview.Entries, retry.Entries) {
		t.Fatal("partial retry advanced", status, retry)
	}
}

func BenchmarkDNSPageHandler(b *testing.B) {
	for _, n := range []int{30, 3000, 300000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "dns.log")
			stamp := time.Now().Add(-time.Minute).Format("2006/01/02 15:04:05.000000")
			if err := os.WriteFile(path, []byte(strings.Repeat(stamp+" dnsmasq[1]: query[A] fixture.invalid from 192.0.2.1\n", n)), 0600); err != nil {
				b.Fatal(err)
			}
			s := &Server{StorageRunner: &accessPageRunner{}}
			r := httptest.NewRequest("GET", "/api/logs?kind=dns", nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.handleDNSLogPage(w, r, path)
				if w.Code != 200 || strings.Contains(w.Body.String(), `"incomplete":true`) {
					b.Fatal(w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestDNSEpochIsKnownTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	os.WriteFile(path, []byte("query[A] unknown.invalid from 192.0.2.1\n"), 0600)
	run := &accessPageRunner{rows: []string{`{"__CURSOR":"epoch","__REALTIME_TIMESTAMP":"0","_SYSTEMD_UNIT":"netos-unbound.service","MESSAGE":"info: 192.0.2.1 epoch.invalid. A IN"}`}}
	p, status := dnsPageRequest(t, &Server{StorageRunner: run}, path, "")
	if status != 200 || len(p.Entries) != 1 || !strings.Contains(p.Entries[0].Message, "unknown.invalid") || len(p.Warnings) != 1 {
		t.Fatal(status, p)
	}
}
