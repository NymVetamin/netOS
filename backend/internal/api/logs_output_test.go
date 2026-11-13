package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

type overflowingLogRunner struct{ accessLogRunner }

func (r overflowingLogRunner) Run(context.Context, string, ...string) (string, error) {
	return r.raw, fmt.Errorf("journalctl: %w", system.ErrOutputLimit)
}

func TestLogsDiscardOverflowAndRecover(t *testing.T) {
	raw := vpnPageRow(0, "main[alice]:192.0.2.2:42 user logged in")
	s := &Server{StorageRunner: overflowingLogRunner{accessLogRunner{raw: raw}}}
	for attempt := 0; attempt < 3; attempt++ {
		r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, r)
		if attempt == 0 {
			if w.Code != 502 {
				t.Fatal("overflow accepted", w.Body.String())
			}
		} else {
			var d struct {
				Entries  []logEntry
				Warnings []string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 || len(d.Entries) != 1 || len(d.Warnings) != 0 {
				t.Fatal("retry failed", w.Body.String(), err)
			}
		}
		s.StorageRunner = accessLogRunner{raw: raw}
	}
}
