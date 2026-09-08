package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestApplyRejectsMaintenanceBeforeCreatingRevision(t *testing.T) {
	for _, tc := range []struct{ name, timer, service string }{
		{"scheduled", "ActiveState=active\nSubState=waiting\n", "ActiveState=inactive\n"},
		{"running", "ActiveState=inactive\n", "ActiveState=active\nSubState=running\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cookie, csrf := newAuthedServer(t)
			initializeAPIEngine(t, s)
			s.Maintenance = &Maintenance{Runner: pendingMaintenanceRunner{tc.timer, tc.service}, Unit: "netos-maintenance"}
			before, err := s.Store.ListRevisions(100)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(fmt.Sprintf(`{"draft_version":%d}`, s.draftVersion))
			w := serveAuthed(s.Routes(), http.MethodPost, "/api/config/apply", body, cookie, csrf)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "операция обслуживания") {
				t.Fatalf("apply during maintenance: status=%d body=%s", w.Code, w.Body.String())
			}
			after, err := s.Store.ListRevisions(100)
			if err != nil || len(after) != len(before) {
				t.Fatalf("rejected apply created a revision: before=%d after=%d err=%v", len(before), len(after), err)
			}
		})
	}
}

func TestApplyRejectsAnotherApplyingRequest(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	initializeAPIEngine(t, s)
	s.draftApplying = true
	body := []byte(fmt.Sprintf(`{"draft_version":%d}`, s.draftVersion))
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/config/apply", body, cookie, csrf)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "идёт применение") || !s.draftApplying {
		t.Fatalf("concurrent apply status=%d applying=%v", w.Code, s.draftApplying)
	}
}
