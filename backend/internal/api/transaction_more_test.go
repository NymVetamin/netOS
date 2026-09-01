package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

type transactionSubsystem struct {
	applied []string
	planErr bool
}

func (s *transactionSubsystem) Name() string { return "firewall" }
func (s *transactionSubsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	if s.planErr {
		return nil, fmt.Errorf("injected plan failure")
	}
	if old != nil && old.System.Hostname == next.System.Hostname {
		return nil, nil
	}
	return []apply.Action{{Subsystem: "firewall", Kind: "update", Target: "test", Disruptive: true}}, nil
}

func TestPlanReportsSubsystemFailure(t *testing.T) {
	s, _, _, subsystem := transactionServer(t)
	subsystem.planErr = true
	w := httptest.NewRecorder()
	s.handlePlan(w, httptest.NewRequest(http.MethodPost, "/api/config/plan", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "injected plan failure") {
		t.Fatalf("plan failure status=%d body=%s", w.Code, w.Body.String())
	}
}
func (s *transactionSubsystem) Apply(ctx context.Context, cfg *config.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.applied = append(s.applied, cfg.System.Hostname)
	return nil
}
func (s *transactionSubsystem) Health(ctx context.Context, _ *config.Config) error {
	return ctx.Err()
}

func transactionServer(t *testing.T) (*Server, *http.Cookie, string, *transactionSubsystem) {
	t.Helper()
	s, cookie, csrf := newAuthedServer(t)
	logger := &lifecycleLogger{}
	engine := apply.NewEngine(logger, false)
	subsystem := &transactionSubsystem{}
	if err := engine.Register(subsystem); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Apply(context.Background(), config.Default(), 0, false); err != nil {
		t.Fatal(err)
	}
	engine.OnRollback = func(info apply.RollbackInfo) {
		if err := s.Store.SetRevisionState(info.Revision, store.StateRolledBack); err != nil {
			t.Errorf("rollback revision state: %v", err)
		}
	}
	s.Engine, s.Logger = engine, logger
	return s, cookie, csrf, subsystem
}

func applyDraft(t *testing.T, s *Server, cookie *http.Cookie, csrf, hostname string) int64 {
	t.Helper()
	cfg := *s.Engine.Current()
	cfg.System.Hostname = hostname
	s.draftMu.Lock()
	s.draft = &cfg
	version := s.draftVersion
	s.draftMu.Unlock()
	body, err := json.Marshal(applyRequest{Comment: hostname, DraftVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/config/apply", body, cookie, csrf)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"needs_confirm":true`) {
		t.Fatalf("apply %s status=%d body=%s", hostname, w.Code, w.Body.String())
	}
	var result apply.Result
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Revision
}

func TestConfigConfirmAndDisconnectedManualRollback(t *testing.T) {
	s, cookie, csrf, subsystem := transactionServer(t)
	firstRevision := applyDraft(t, s, cookie, csrf, "confirmed-router")
	if pending, _ := s.Engine.Pending(); !pending {
		t.Fatal("disruptive apply did not enter pending state")
	}

	current := *s.Engine.Current()
	current.System.Hostname = "cannot-save-while-pending"
	body, _ := json.Marshal(&current)
	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body)))
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("If-Match", strconv.FormatUint(s.draftVersion, 10))
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("save while pending status=%d body=%s", w.Code, w.Body.String())
	}

	w = serveAuthed(s.Routes(), http.MethodPost, "/api/config/confirm", nil, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", w.Code, w.Body.String())
	}
	revision, err := s.Store.Revision(firstRevision)
	if err != nil || revision.State != store.StateActive {
		t.Fatalf("confirmed revision=%+v err=%v", revision, err)
	}
	if pending, _ := s.Engine.Pending(); pending || s.draft != nil {
		t.Fatalf("confirm left pending=%v draft=%v", pending, s.draft)
	}

	secondRevision := applyDraft(t, s, cookie, csrf, "rollback-router")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Simulate the browser connection disappearing during network restore.
	req = httptest.NewRequest(http.MethodPost, "/api/config/rollback", nil).WithContext(ctx)
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	w = httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback after disconnect status=%d body=%s", w.Code, w.Body.String())
	}
	if got := s.Engine.Current().System.Hostname; got != "confirmed-router" {
		t.Fatalf("rollback restored hostname=%q", got)
	}
	revision, err = s.Store.Revision(secondRevision)
	if err != nil || revision.State != store.StateRolledBack {
		t.Fatalf("rolled back revision=%+v err=%v", revision, err)
	}
	if len(subsystem.applied) < 4 || subsystem.applied[len(subsystem.applied)-1] != "confirmed-router" {
		t.Fatalf("subsystem lifecycle=%v", subsystem.applied)
	}
	if s.draft != nil {
		t.Fatalf("rollback retained rejected draft: %+v", s.draft)
	}
}

func TestNewClearsDraftForTimeoutRollbackCallback(t *testing.T) {
	engine := apply.NewEngine(&lifecycleLogger{}, true)
	previousCalled := false
	engine.OnRollback = func(apply.RollbackInfo) { previousCalled = true }
	s := New(nil, engine, nil, &lifecycleLogger{})
	cfg := config.Default()
	s.draft = cfg
	engine.OnRollback(apply.RollbackInfo{Reason: "timeout"})
	if !previousCalled || s.draft != nil || s.draftVersion != 2 {
		t.Fatalf("previous=%v draft=%+v version=%d", previousCalled, s.draft, s.draftVersion)
	}
}

func TestDraftPreconditionAndBusyBranches(t *testing.T) {
	s, cookie, csrf, _ := transactionServer(t)
	h := s.Routes()
	for _, tc := range []struct {
		header string
		want   int
	}{
		{"", http.StatusPreconditionRequired},
		{"not-a-number", http.StatusBadRequest},
		{"999", http.StatusConflict},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/config/discard", nil)
		req.AddCookie(cookie)
		req.Header.Set(csrfHeader, csrf)
		if tc.header != "" {
			req.Header.Set("If-Match", tc.header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("If-Match %q status=%d want=%d body=%s", tc.header, w.Code, tc.want, w.Body.String())
		}
	}
	s.draftMu.Lock()
	s.draftApplying = true
	version := s.draftVersion
	s.draftMu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "/api/config/discard", nil)
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("If-Match", strconv.FormatUint(version, 10))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("busy discard status=%d body=%s", w.Code, w.Body.String())
	}
}
