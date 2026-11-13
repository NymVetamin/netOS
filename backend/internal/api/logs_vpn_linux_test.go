//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
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
		r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		start := time.Now()
		s.handleLogs(w, r)
		var d struct {
			Entries  []logEntry
			Warnings []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 || len(d.Warnings) != 0 {
			t.Fatal(w.Body.String(), err)
		}
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
				r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
				r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
				w := httptest.NewRecorder()
				start := time.Now()
				s.handleLogs(w, r)
				var d struct {
					Entries  []logEntry
					Warnings []string
				}
				if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 || len(d.Warnings) != 0 {
					t.Fatal(w.Body.String(), err)
				}
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
