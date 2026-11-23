package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

type transactionSubsystem struct {
	applied         []string
	planErr         bool
	failNextApplies int
}

func TestImmediateApplySurvivesCommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "router.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	logger := &lifecycleLogger{}
	s := &Server{Store: st, Engine: apply.NewEngine(logger, false), Logger: logger}
	subsystem := &transactionSubsystem{}
	if err := s.Engine.Register(subsystem); err != nil {
		t.Fatal(err)
	}
	old := config.Default()
	oldID, err := st.CreateRevision(old, "admin", "initial")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Engine.ApplyWithCommit(context.Background(), old, oldID, false, nil, st.MarkActive); err != nil {
		t.Fatal(err)
	}
	next := *old
	next.System.Timezone = "Asia/Tokyo"
	s.draft = &next
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleApply(w, httptest.NewRequest(http.MethodPost, "/api/config/apply", strings.NewReader("{}")))
		return w
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_active BEFORE UPDATE OF state ON revisions
		WHEN NEW.state='active' BEGIN SELECT RAISE(ABORT,'commit failed'); END`); err != nil {
		t.Fatal(err)
	}
	w := request()
	if w.Code != 500 || !strings.Contains(w.Body.String(), "commit failed") {
		t.Fatalf("failed commit: %d %s", w.Code, w.Body.String())
	}
	active, err := st.ActiveRevision()
	if err != nil || active.ID != oldID || s.Engine.Current() != old || s.draft != &next {
		t.Fatalf("active=%+v current restored=%v draft retained=%v err=%v", active, s.Engine.Current() == old, s.draft == &next, err)
	}
	last, err := st.LatestRevision()
	if err != nil || last.State != store.StateRolledBack || len(subsystem.applied) != 3 {
		t.Fatalf("rollback: revision=%+v applies=%v err=%v", last, subsystem.applied, err)
	}
	if _, err := db.Exec("DROP TRIGGER reject_active"); err != nil {
		t.Fatal(err)
	}
	w = request()
	active, err = st.ActiveRevision()
	if w.Code != 200 || err != nil || active.Config.System.Timezone != next.System.Timezone || s.Engine.Current() != &next || s.draft != nil {
		t.Fatalf("retry: %d %s active=%+v err=%v", w.Code, w.Body.String(), active, err)
	}
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
	if s.failNextApplies > 0 {
		s.failNextApplies--
		return fmt.Errorf("injected apply failure")
	}
	return nil
}

func TestApplyRecordsActualRecovery(t *testing.T) {
	s, cookie, csrf, subsystem := transactionServer(t)
	cfg := *s.Engine.Current()
	cfg.System.Hostname = "changed"
	draft := s.privateDraftLocked("admin")
	draft.Config = &cfg
	body, err := json.Marshal(applyRequest{DraftVersion: draft.Version})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		failures int
		state    string
		message  string
	}{
		{2, store.StateFailed, "откат не удался"},
		{1, store.StateRolledBack, apply.ErrRestored.Error()},
	} {
		subsystem.failNextApplies = tc.failures
		w := serveAuthed(s.Routes(), http.MethodPost, "/api/config/apply", body, cookie, csrf)
		if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), tc.message) {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		revision, err := s.Store.LatestRevision()
		if err != nil || revision.State != tc.state || draft.Config != &cfg {
			t.Fatalf("revision=%+v draft retained=%v err=%v", revision, draft.Config == &cfg, err)
		}
	}
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/config/apply", body, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}
	revision, _ := s.Engine.PendingRevision()
	w = serveRevisionAction(s.Routes(), "confirm", revision, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
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
	d := s.privateDraftLocked("admin")
	d.Config = &cfg
	version := d.Version
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

	w = serveRevisionAction(s.Routes(), "confirm", firstRevision, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", w.Code, w.Body.String())
	}
	revision, err := s.Store.Revision(firstRevision)
	if err != nil || revision.State != store.StateActive {
		t.Fatalf("confirmed revision=%+v err=%v", revision, err)
	}
	if pending, _ := s.Engine.Pending(); pending || s.privateDrafts["admin"].Config != nil {
		t.Fatalf("confirm left pending=%v draft=%v", pending, s.draft)
	}

	secondRevision := applyDraft(t, s, cookie, csrf, "rollback-router")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Simulate the browser connection disappearing during network restore.
	req = httptest.NewRequest(http.MethodPost, "/api/config/rollback", nil).WithContext(ctx)
	req.Header.Set("If-Match", strconv.FormatInt(secondRevision, 10))
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
	if s.privateDrafts["admin"].Config != nil {
		t.Fatalf("rollback retained rejected draft: %+v", s.privateDrafts["admin"])
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
