//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationServiceLogs(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized systemd test machine")
	}
	run := &system.Exec{Timeout: 10 * time.Second}
	ctx := context.Background()
	for _, n := range []int{30, 3000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			name := fmt.Sprintf("netos-qa-log-%d-%d.service", os.Getpid(), n)
			ready := filepath.Join(t.TempDir(), "ready")
			script := fmt.Sprintf("printf '<4>qa-service-warning\\n'; i=0; while [ $i -lt %d ]; do printf '<6>info: 127.0.0.1 example.org. A IN NOERROR 0.1 0 74\\n'; i=$((i+1)); done; touch '%s'; sleep 120", n, ready)
			t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", name); run.Run(ctx, "systemctl", "reset-failed", name) })
			if out, err := run.Run(ctx, "systemd-run", "--unit="+name, "--description=Service log fixture", "--property=SyslogLevelPrefix=yes", "/bin/sh", "-c", script); err != nil {
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
			for repeat := 0; repeat < 3; repeat++ {
				s := &Server{StorageRunner: run}
				start := time.Now()
				data := readAllJournalPages(t, s, "services")
				elapsed := time.Since(start)
				encoded, _ := json.Marshal(data)
				warning, started := false, false
				for _, e := range data.Entries {
					if e.Unit != name {
						continue
					}
					warning = warning || e.Message == "qa-service-warning"
					started = started || strings.HasPrefix(e.Message, "Started ")
					if strings.HasPrefix(e.Message, "info:") && strings.Contains(e.Message, "NOERROR") {
						t.Error("DNS reply polluted service logs")
					}
				}
				if !warning || !started {
					t.Errorf("noise evicted lifecycle/warning: warning=%v started=%v", warning, started)
				}
				t.Logf("noise=%d repeat=%d handler=%s bytes=%d rows=%d", n, repeat, elapsed, len(encoded), len(data.Entries))
			}
		})
	}
}

func TestIntegrationServiceLogsFailureAndRetry(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized systemd test machine")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 10 * time.Second}
	name := fmt.Sprintf("netos-qa-log-retry-%d.service", os.Getpid())
	t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", name); run.Run(ctx, "systemctl", "reset-failed", name) })
	if _, err := run.Run(ctx, "systemd-run", "--unit="+name, "--wait", "--property=Type=oneshot", "/bin/false"); err == nil {
		t.Fatal("fixture did not fail")
	}
	if out, err := run.Run(ctx, "systemctl", "reset-failed", name); err != nil {
		t.Fatal(out, err)
	}
	if out, err := run.Run(ctx, "systemd-run", "--unit="+name, "--wait", "--property=Type=oneshot", "/bin/true"); err != nil {
		t.Fatal(out, err)
	}
	if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
		t.Fatal(out, err)
	}
	data := readAllJournalPages(t, &Server{StorageRunner: run}, "services")
	failed, completed := false, false
	for _, e := range data.Entries {
		if e.Unit == name {
			failed = failed || e.Event == "Служба перешла в ошибку"
			completed = completed || e.Event == "Служба запущена"
		}
	}
	if !failed || !completed {
		t.Fatalf("missing failure/retry: failed=%v completed=%v", failed, completed)
	}
	for _, level := range []string{"error", "info"} {
		filtered := readAllJournalPages(t, &Server{StorageRunner: run}, "services", "result="+level+"&object="+name)
		if len(filtered.Entries) == 0 {
			t.Fatal("real service type filter lost events", level)
		}
		for _, e := range filtered.Entries {
			if e.Severity != level || e.Unit != name {
				t.Fatal("wrong filtered service event", e)
			}
		}
	}
}

func TestIntegrationServicePageEquivalentLegacy(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized systemd test machine")
	}
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	s := &Server{StorageRunner: run}
	start := time.Now()
	all := readAllJournalPages(t, s, "services")
	pagedTime := time.Since(start)
	base := []string{"--no-pager", "--quiet", "-o", "json", "-n", "3000", "--since=" + journalPageTime(all.From), "--until=" + journalPageTime(all.CapturedAt)}
	queries := [][]string{serviceJournalMatches(), {"-u", "netosd.service", "--grep=\\[(пред|ошиб)\\]", "PRIORITY=5", "PRIORITY=6", "PRIORITY=7"}}
	counts := map[string]int{}
	oldCount := 0
	start = time.Now()
	for _, query := range queries {
		raw, err := run.Run(context.Background(), "journalctl", append(append([]string{}, base...), query...)...)
		if err != nil && !emptyJournalMatch(raw, err) {
			t.Fatal(err)
		}
		rows, err := parseJournalEntries(raw, "services")
		if err != nil || len(rows) >= 3000 {
			t.Fatal("comparison fixture exceeded bound", len(rows), err)
		}
		oldCount += len(rows)
		for _, e := range rows {
			e.ID = ""
			b, _ := json.Marshal(e)
			counts[string(b)]++
		}
	}
	legacyTime := time.Since(start)
	for _, e := range all.Entries {
		e.ID = ""
		b, _ := json.Marshal(e)
		counts[string(b)]--
	}
	for _, n := range counts {
		if n != 0 {
			t.Fatal("service event multisets differ")
		}
	}
	t.Logf("same snapshot events=%d old two commands+parse=%s full paginated API=%s", oldCount, legacyTime, pagedTime)
}
