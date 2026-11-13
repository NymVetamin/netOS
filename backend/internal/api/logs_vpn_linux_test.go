//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

// Run after TestIntegrationOcservAndOpenConnect on the authorized test machine.
// This reads actual daemon records, rather than emitting a simulated log line.
func TestIntegrationVPNLogs(t *testing.T) {
	if os.Getenv("NETOS_LOGS_OCSERV_FIXTURE") != "1" {
		t.Skip("requires real OpenConnect fixture")
	}
	s := &Server{StorageRunner: &system.Exec{Timeout: 5 * time.Second}}
	for i := 0; i < 3; i++ {
		start := time.Now()
		d := readAllVPNPages(t, s)
		login, disconnect := false, false
		for _, e := range d.Entries {
			if e.Server != "srv998" || e.User != "integration" {
				continue
			}
			if e.Protocol != "openconnect" || e.Address == "" {
				t.Fatalf("lost peer metadata: %+v", e)
			}
			login = login || e.Result == "success"
			disconnect = disconnect || e.Event == "VPN-соединение завершено" && e.Result == "info"
		}
		if !login || !disconnect {
			t.Fatalf("real VPN events missing: login=%v disconnect=%v", login, disconnect)
		}
		t.Logf("real journal handler: %s, %d events", time.Since(start), len(d.Entries))
	}
}

// Requires the real IKEv2 success/refusal and two-client L2TP fixture runs.
func TestIntegrationVPNTunnelProtocols(t *testing.T) {
	if os.Getenv("NETOS_LOGS_TUNNEL_FIXTURE") != "1" {
		t.Skip("requires real IKEv2/L2TP fixtures")
	}
	s := &Server{StorageRunner: &system.Exec{Timeout: 5 * time.Second}}
	for repeat := 0; repeat < 3; repeat++ {
		start := time.Now()
		d := readAllVPNPages(t, s)
		ikeSuccess, ikeRefused, ikeAddress, l2tpFirst, l2tpSecond, l2tpAddress, l2tpRefused := false, false, false, false, false, false, false
		for _, e := range d.Entries {
			if e.Protocol == "ikev2" && e.Server == "srv997" {
				ikeSuccess = ikeSuccess || e.User == "integration" && e.Result == "success"
				ikeRefused = ikeRefused || e.User == "integration" && e.Result == "failure"
				ikeAddress = ikeAddress || e.Address == "192.0.2.2" && e.Result == "success"
			}
			if e.Protocol == "l2tp" && e.Server == "srv996" {
				l2tpFirst = l2tpFirst || e.User == "qa-l2tp" && e.Result == "success"
				l2tpSecond = l2tpSecond || e.User == "qa-l2tp2" && e.Result == "success"
				l2tpAddress = l2tpAddress || e.Address == "192.0.2.14" && e.Result == "info"
				l2tpRefused = l2tpRefused || e.User == "qa-l2tp" && e.Result == "failure"
			}
		}
		if !ikeSuccess || !ikeRefused || !ikeAddress || !l2tpFirst || !l2tpSecond || !l2tpAddress || !l2tpRefused {
			t.Fatalf("missing real events IKE success=%v refused=%v address=%v L2TP first=%v second=%v address=%v refused=%v", ikeSuccess, ikeRefused, ikeAddress, l2tpFirst, l2tpSecond, l2tpAddress, l2tpRefused)
		}
		t.Logf("real mixed VPN handler=%s events=%d", time.Since(start), len(d.Entries))
	}
}

func TestIntegrationVPNLogNoise(t *testing.T) {
	if os.Getenv("NETOS_LOGS_OCSERV_FIXTURE") != "1" {
		t.Skip("requires authorized systemd machine")
	}
	run := &system.Exec{Timeout: 10 * time.Second}
	ctx := context.Background()
	for _, n := range []int{30, 3000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			unit := fmt.Sprintf("netos-ocserv-srv%d.service", 9000000+os.Getpid()+n)
			ready := filepath.Join(t.TempDir(), "ready")
			script := fmt.Sprintf("printf 'main[noise-fixture]:192.0.2.2:42 user logged in\\n'; i=0; while [ $i -lt %d ]; do printf 'worker: routine heartbeat\\n'; i=$((i+1)); done; touch '%s'; sleep 60", n, ready)
			t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", unit); run.Run(ctx, "systemctl", "reset-failed", unit) })
			if out, err := run.Run(ctx, "systemd-run", "--unit="+unit, "--description=VPN log noise fixture", "/bin/sh", "-c", script); err != nil {
				t.Fatal(out, err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("emitter timeout")
				}
				time.Sleep(25 * time.Millisecond)
			}
			if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
				t.Fatal(out, err)
			}
			s := &Server{StorageRunner: run}
			for i := 0; i < 3; i++ {
				start := time.Now()
				d := readAllVPNPages(t, s)
				found := false
				for _, e := range d.Entries {
					if e.Unit == unit && e.User == "noise-fixture" && e.Result == "success" {
						found = true
					}
				}
				if !found {
					t.Fatal("noise evicted actual event")
				}
				t.Logf("noise=%d full handler=%s", n, time.Since(start))
			}
		})
	}
}

func readAllVPNPages(t *testing.T, s *Server, filter ...string) vpnLogPage {
	t.Helper()
	all := vpnLogPage{}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 200; page++ {
		query := "/api/logs?kind=vpn&cursor=" + url.QueryEscape(cursor)
		if len(filter) > 0 {
			query += "&" + filter[0]
		}
		r := httptest.NewRequest("GET", query, nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		start := time.Now()
		s.handleLogs(w, r)
		var d vpnLogPage
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 || len(d.Warnings) != 0 {
			t.Fatal(w.Body.String(), err)
		}
		if len(d.Entries) > logPageSize || d.Scanned > logScanSize {
			t.Fatal("unbounded page")
		}
		if page == 0 {
			all.CapturedAt = d.CapturedAt
			all.From = d.From
		} else if !all.CapturedAt.Equal(d.CapturedAt) || !all.From.Equal(d.From) {
			t.Fatal("snapshot boundary changed")
		}
		for _, e := range d.Entries {
			if seen[e.ID] {
				t.Fatal("duplicate record", e.ID)
			}
			seen[e.ID] = true
		}
		all.Entries = append(all.Entries, d.Entries...)
		t.Logf("page=%d scanned=%d events=%d time=%s", page, d.Scanned, len(d.Entries), time.Since(start))
		if d.Next == "" {
			return all
		}
		if d.Next == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = d.Next
	}
	t.Fatal("page budget exhausted")
	return all
}

type emptyJournalRunner struct {
	*system.Exec
	directory string
}

func (e emptyJournalRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return e.Exec.Run(ctx, name, append(args, "--directory="+e.directory)...)
}

func TestIntegrationVPNPageFiltersAndMissingAnchor(t *testing.T) {
	if os.Getenv("NETOS_LOGS_TUNNEL_FIXTURE") != "1" {
		t.Skip("requires real IKEv2 refusal fixture")
	}
	s := &Server{StorageRunner: &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}}
	d := readAllVPNPages(t, s, "result=failure&object=integration")
	if len(d.Entries) == 0 {
		t.Fatal("real refusal missing")
	}
	for _, e := range d.Entries {
		if e.Result != "failure" || e.User != "integration" {
			t.Fatal("filter not applied", e)
		}
	}
	r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
	w := httptest.NewRecorder()
	s.handleLogs(w, r)
	var first vpnLogPage
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != 200 || first.Next == "" {
		t.Fatal("requires paginated real journal", w.Body.String(), err)
	}
	// A real empty journal directory models a source whose anchor was removed;
	// never vacuum the test host's shared journal to manufacture this condition.
	s.StorageRunner = emptyJournalRunner{Exec: &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}, directory: t.TempDir()}
	r = httptest.NewRequest("GET", "/api/logs?kind=vpn&cursor="+url.QueryEscape(first.Next), nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
	w = httptest.NewRecorder()
	s.handleLogs(w, r)
	if w.Code != 409 {
		t.Fatal("missing anchor silently accepted", w.Code, w.Body.String())
	}
}

func TestIntegrationVPNPageEquivalentLegacy(t *testing.T) {
	if os.Getenv("NETOS_LOGS_TUNNEL_FIXTURE") != "1" {
		t.Skip("requires real VPN journal fixture")
	}
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	s := &Server{StorageRunner: run}
	start := time.Now()
	all := readAllVPNPages(t, s)
	pagedTime := time.Since(start)
	start = time.Now()
	raw, err := run.Run(context.Background(), "journalctl", "--no-pager", "--quiet", "-o", "json", "-n", "300", "--since="+journalPageTime(all.From), "--until="+journalPageTime(all.CapturedAt), "-u", "netos-ocserv-srv*.service", "-u", "netos-strongswan.service", "-u", "netos-vpn-l2tp-srv*.service", "--grep="+ocservEventPattern+"|"+ikeEventPattern+"|"+l2tpEventPattern)
	if err != nil {
		t.Fatal(err)
	}
	old, err := parseJournalEntries(raw, "vpn")
	if err != nil || len(old) >= 300 {
		t.Fatal("comparison requires fewer than legacy limit", len(old), err)
	}
	legacyTime := time.Since(start)
	counts := map[string]int{}
	for _, e := range old {
		e.ID = ""
		b, _ := json.Marshal(e)
		counts[string(b)]++
	}
	for _, e := range all.Entries {
		e.ID = ""
		b, _ := json.Marshal(e)
		counts[string(b)]--
	}
	for _, n := range counts {
		if n != 0 {
			t.Fatal("old and paginated event multisets differ")
		}
	}
	t.Logf("same snapshot events=%d legacy command+parse=%s full paginated API=%s", len(old), legacyTime, pagedTime)
}
