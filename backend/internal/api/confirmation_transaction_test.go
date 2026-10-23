package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

type classifiedTransaction struct {
	transactionSubsystem
	actions    []apply.Action
	failHealth bool
}

func (s *classifiedTransaction) Plan(old, next *config.Config) ([]apply.Action, error) {
	if old != nil && old.System.Hostname == next.System.Hostname {
		return nil, nil
	}
	return s.actions, nil
}

func (s *classifiedTransaction) Health(ctx context.Context, cfg *config.Config) error {
	if s.failHealth && cfg.System.Hostname == "classified-router" {
		return fmt.Errorf("injected health failure")
	}
	return ctx.Err()
}

func TestClassifiedConfirmationThroughAuthenticatedAPI(t *testing.T) {
	for _, mode := range []string{"safe", "required", "unknown", "mixed", "disruptive", "health failure"} {
		t.Run(mode, func(t *testing.T) {
			s, cookie, csrf := newAuthedServer(t)
			actions := []apply.Action{{Kind: "update", Target: "classification test", Confirmation: apply.ConfirmationSafe}}
			switch mode {
			case "required":
				actions[0].Confirmation = apply.ConfirmationRequired
			case "unknown":
				actions[0].Confirmation = "unrecognized"
			case "mixed":
				actions = append(actions, apply.Action{Kind: "update", Target: "risky companion", Confirmation: apply.ConfirmationRequired})
			case "disruptive":
				actions[0].Disruptive = true
			}
			subsystem := &classifiedTransaction{actions: actions, failHealth: mode == "health failure"}
			engine := apply.NewEngine(&lifecycleLogger{}, false)
			if err := engine.Register(subsystem); err != nil {
				t.Fatal(err)
			}
			base := config.Default()
			if _, err := engine.Apply(context.Background(), base, 0, false); err != nil {
				t.Fatal(err)
			}
			s.Engine = engine
			defer engine.Rollback(context.Background())
			next := *base
			next.System.Hostname = "classified-router"
			draft := s.privateDraftLocked("admin")
			draft.Config = &next
			body, _ := json.Marshal(applyRequest{DraftVersion: draft.Version})
			h := s.Routes()
			denied := serveAuthed(h, http.MethodPost, "/api/config/apply", body, cookie, "wrong-csrf")
			if denied.Code != http.StatusForbidden || engine.Current().System.Hostname != base.System.Hostname {
				t.Fatalf("CSRF bypass: %d", denied.Code)
			}
			w := serveAuthed(h, http.MethodPost, "/api/config/apply", body, cookie, csrf)
			pending, _ := engine.Pending()
			if mode == "health failure" {
				if w.Code == http.StatusOK || pending || engine.Current().System.Hostname != base.System.Hostname {
					t.Fatalf("failed safe apply not rolled back: %d pending=%v", w.Code, pending)
				}
				if got := subsystem.applied[len(subsystem.applied)-1]; got != base.System.Hostname {
					t.Fatalf("rollback not applied: %s", got)
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("apply: %d %s", w.Code, w.Body.String())
			}
			var result apply.Result
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			wantPending := mode != "safe"
			if pending != wantPending || result.NeedsConfirm != wantPending {
				t.Fatalf("pending=%v want=%v", pending, wantPending)
			}
			if engine.Current().System.Hostname != next.System.Hostname {
				t.Fatal("configuration not applied")
			}
			if wantPending {
				confirmed := serveAuthed(h, http.MethodPost, "/api/config/confirm", nil, cookie, csrf)
				if confirmed.Code != http.StatusOK {
					t.Fatalf("confirm: %d %s", confirmed.Code, confirmed.Body.String())
				}
			}
			revision, err := s.Store.Revision(result.Revision)
			if err != nil || revision.State != store.StateActive {
				t.Fatalf("revision not active: %+v %v", revision, err)
			}
			if s.privateDrafts["admin"].Config != nil {
				t.Fatal("completed apply retained draft")
			}
		})
	}
}
