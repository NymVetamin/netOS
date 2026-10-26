package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

type heldPreview struct {
	transactionSubsystem
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *heldPreview) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	first := false
	p.once.Do(func() { first = true; close(p.entered) })
	if !first {
		return p.Plan(old, next)
	}
	select {
	case <-p.release:
		return p.Plan(old, next)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestPrivatePlanDoesNotBlockDraftsAndRejectsStaleResults(t *testing.T) {
	for _, change := range []string{"none", "edit", "discard", "other-user", "applying", "active-config", "cancel"} {
		t.Run(change, func(t *testing.T) {
			s, _, _, _ := transactionServer(t)
			p := &heldPreview{entered: make(chan struct{}), release: make(chan struct{})}
			if err := s.Engine.Register(p); err != nil {
				t.Fatal(err)
			}
			var release sync.Once
			unblock := func() { release.Do(func() { close(p.release) }) }
			defer unblock()
			request := func(ctx context.Context, user, method, path string, cfg *config.Config, version uint64) *httptest.ResponseRecorder {
				body, _ := json.Marshal(cfg)
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r = r.WithContext(context.WithValue(ctx, ctxUser, user))
				r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
				r.Header.Set("If-Match", strconv.FormatUint(version, 10))
				w := httptest.NewRecorder()
				s.handlePrivateConfig(w, r)
				return w
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- request(ctx, "alice", "POST", "/api/config/plan", nil, 0) }()
			select {
			case <-p.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("planner not reached")
			}
			for _, user := range []string{"alice", "bob"} {
				read := make(chan *httptest.ResponseRecorder, 1)
				go func() { read <- request(context.Background(), user, "GET", "/api/config", nil, 0) }()
				select {
				case w := <-read:
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body.String())
					}
				case <-time.After(time.Second):
					t.Fatal("preview blocked config read for", user)
				}
			}
			switch change {
			case "edit", "other-user", "discard":
				user := "alice"
				if change == "other-user" {
					user = "bob"
				}
				cfg, _ := objectConfig(configObject(s.Engine.Current()))
				cfg.System.Hostname = "edited-router"
				method, path := "PUT", "/api/config"
				if change == "discard" {
					method, path = "POST", "/api/config/discard"
				}
				w := request(context.Background(), user, method, path, cfg, 1)
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
			case "applying":
				s.draftMu.Lock()
				s.draftApplying = true
				s.draftMu.Unlock()
			case "active-config":
				cfg, _ := objectConfig(configObject(s.Engine.Current()))
				cfg.System.Hostname = "applied-router"
				if _, err := s.Engine.Apply(context.Background(), cfg, 0, false); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			unblock()
			w := <-done
			want := 409
			if change == "none" || change == "other-user" {
				want = 200
			}
			if change == "cancel" {
				want = 500
			}
			if w.Code != want {
				t.Fatalf("want %d got %d: %s", want, w.Code, w.Body.String())
			}
			s.draftMu.Lock()
			s.draftApplying = false
			s.draftMu.Unlock()
			// A rejected/failed preview must not poison the next request.
			w = request(context.Background(), "alice", "POST", "/api/config/plan", nil, 0)
			if w.Code != 200 {
				t.Fatal("retry failed", w.Code, w.Body.String())
			}
		})
	}
}
