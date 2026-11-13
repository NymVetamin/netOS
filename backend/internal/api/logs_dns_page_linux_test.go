//go:build linux

package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationDNSPages(t *testing.T) {
	if os.Getenv("NETOS_DNS_PAGE_INTEGRATION") != "1" {
		t.Skip("requires authorized systemd machine with no installed netos DNS unit")
	}
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	ctx := context.Background()
	unit := "netos-dnsproxy.service"
	state, err := run.Run(ctx, "systemctl", "show", unit, "--property=LoadState", "--value")
	if err != nil || strings.TrimSpace(state) != "not-found" {
		t.Fatal("fixture unit already exists", state, err)
	}
	for _, noise := range []int{30, 3000} {
		t.Run(fmt.Sprint(noise), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dns.log")
			ready := filepath.Join(t.TempDir(), "ready")
			stamp := time.Now().Format("2006/01/02 15:04:05.000000")
			if err := os.WriteFile(path, []byte(strings.Repeat(stamp+" dnsmasq[1]: query[A] file-fixture.invalid from 192.0.2.1\n", 240)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".1", []byte(stamp+" dnsmasq[1]: query[A] archive-fixture.invalid from 192.0.2.1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			script := fmt.Sprintf("printf 'info: 192.0.2.1 journal-fixture.invalid. A IN\\n'; i=0; while [ $i -lt %d ]; do printf 'routine noise\\n'; i=$((i+1)); done; touch '%s'; sleep 60", noise, ready)
			t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", unit); run.Run(ctx, "systemctl", "reset-failed", unit) })
			if out, err := run.Run(ctx, "systemd-run", "--unit="+unit, "--description=DNS paging fixture", "/bin/sh", "-c", script); err != nil {
				t.Fatal(out, err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("fixture timeout")
				}
				time.Sleep(25 * time.Millisecond)
			}
			if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
				t.Fatal(out, err)
			}
			s := &Server{StorageRunner: run}
			cursor := ""
			seen := map[string]bool{}
			files, archives, journal := 0, 0, 0
			for page := 0; page < 100; page++ {
				start := time.Now()
				p, status := dnsPageRequest(t, s, path, cursor)
				if status != 200 || p.Incomplete || p.Scanned > 500 || len(p.Entries) > 100 {
					t.Fatal(status, p)
				}
				for _, e := range p.Entries {
					if seen[e.ID] {
						t.Fatal("duplicate", e.ID)
					}
					seen[e.ID] = true
					if strings.Contains(e.Message, "file-fixture.invalid") {
						files++
					}
					if strings.Contains(e.Message, "archive-fixture.invalid") {
						archives++
					}
					if strings.Contains(e.Message, "journal-fixture.invalid") {
						journal++
					}
				}
				t.Logf("noise=%d page=%d scanned=%d events=%d latency=%s", noise, page, p.Scanned, len(p.Entries), time.Since(start))
				cursor = p.Next
				if cursor == "" {
					break
				}
			}
			// Earlier subtests leave genuine journal history, so journal>=1.
			if cursor != "" || files != 240 || archives != 1 || journal < 1 {
				t.Fatal(files, archives, journal, cursor)
			}
		})
	}
}
