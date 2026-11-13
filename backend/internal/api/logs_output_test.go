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
	raw := `{"_SYSTEMD_UNIT":"netos-ocserv-srv12.service","MESSAGE":"main[alice]:192.0.2.2:42 user logged in"}`
	s := &Server{StorageRunner: overflowingLogRunner{accessLogRunner{raw: raw}}}
	for attempt := 0; attempt < 3; attempt++ {
		r := httptest.NewRequest("GET", "/api/logs?kind=vpn", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
		w := httptest.NewRecorder()
		s.handleLogs(w, r)
		var d struct {
			Entries  []logEntry
			Warnings []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
			t.Fatal(w.Body.String(), err)
		}
		if attempt == 0 {
			if len(d.Entries) != 0 || len(d.Warnings) != 1 {
				t.Fatal("overflow was presented as complete history", w.Body.String())
			}
		} else if len(d.Entries) != 1 || len(d.Warnings) != 0 {
			t.Fatal("retry did not recover", w.Body.String())
		}
		s.StorageRunner = accessLogRunner{raw: raw}
	}
}
