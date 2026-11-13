//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationLegacyXrayServices(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized systemd test machine")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 10 * time.Second, MaxOutputBytes: 4 << 20}
	for _, n := range []int{30, 750, 30000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			name := fmt.Sprintf("netos-xray-ch%d%d.service", os.Getpid(), n)
			from := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			// Exercise the historical _COMM path and the current identifier path.
			comm, identifier := "xray", "legacy-xray"
			if n == 750 {
				comm, identifier = "python3", "netos-xray"
			}
			script := fmt.Sprintf("import ctypes\nctypes.CDLL(None).prctl(15,b'%s',0,0,0)\nprint('[Warning] qa-old-warning',flush=True)\nfor i in range(%d): print('from 192.0.2.2:1234 accepted tcp:example.org:443 [in -> out]',flush=True)\nprint('[Error] qa-new-error',flush=True)\n", comm, n)
			t.Cleanup(func() { run.Run(ctx, "systemctl", "stop", name); run.Run(ctx, "systemctl", "reset-failed", name) })
			if out, err := run.Run(ctx, "systemd-run", "--unit="+name, "--description=Xray legacy diagnostic fixture", "--wait", "--property=SyslogIdentifier="+identifier, "--property=LogRateLimitIntervalSec=0", "/usr/bin/python3", "-c", script); err != nil {
				t.Fatal(out, err)
			}
			if out, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
				t.Fatal(out, err)
			}
			for repeat := 0; repeat < 3; repeat++ {
				cursor, warning, failure, scanned := "", 0, 0, 0
				s := &Server{StorageRunner: run}
				started := time.Now()
				for page := 0; page < 100; page++ {
					request := httptest.NewRequest("GET", "/api/logs?kind=services&from="+url.QueryEscape(from)+"&object="+name+"&cursor="+url.QueryEscape(cursor), nil)
					w := httptest.NewRecorder()
					s.handleJournalLogPage(w, request)
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body.String())
					}
					var p journalLogPage
					if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
						t.Fatal(err)
					}
					if p.Scanned > logScanSize || len(p.Entries) > logPageSize {
						t.Fatal("page bound", p.Scanned, len(p.Entries))
					}
					if page == 0 {
						t.Logf("records=%d repeat=%d first-page=%s scanned=%d bytes=%d", n, repeat, time.Since(started), p.Scanned, w.Body.Len())
					}
					scanned += p.Scanned
					for _, e := range p.Entries {
						if e.Message == "[Warning] qa-old-warning" && e.Severity == "warning" {
							warning++
						}
						if e.Message == "[Error] qa-new-error" && e.Severity == "error" {
							failure++
						}
						if strings.HasPrefix(e.Message, "from 192.0.2.2:1234 accepted ") {
							t.Fatal("access noise in Services", e)
						}
					}
					cursor = p.Next
					if cursor == "" {
						break
					}
				}
				if cursor != "" || warning != 1 || failure != 1 {
					t.Fatalf("incomplete/repeated events: cursor=%t warning=%d error=%d", cursor != "", warning, failure)
				}
				t.Logf("records=%d repeat=%d all-pages=%s scanned=%d", n, repeat, time.Since(started), scanned)
			}
		})
	}
}
