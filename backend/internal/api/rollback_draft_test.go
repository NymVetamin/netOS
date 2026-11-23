package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/store"
)

func TestApplyRejectsDraftDiscardedDuringRollback(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(fmt.Sprintf("private=%t", private), func(t *testing.T) {
			fixture, cookie, csrf, sub := transactionServer(t)
			engine := fixture.Engine
			defer engine.Confirm(nil)
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			persist := engine.OnRollback
			engine.OnRollback = func(info apply.RollbackInfo) {
				persist(info)
				close(entered)
				<-release
			}
			s := New(fixture.Store, engine, nil, fixture.Logger)
			s.csrfTokens = fixture.csrfTokens
			h := s.Routes()
			request := func(version uint64) *httptest.ResponseRecorder {
				body := fmt.Sprintf("{\"draft_version\":%d}", version)
				if private {
					return serveAuthed(h, http.MethodPost, "/api/config/apply", []byte(body), cookie, csrf)
				}
				w := httptest.NewRecorder()
				s.handleApply(w, httptest.NewRequest(http.MethodPost, "/api/config/apply", strings.NewReader(body)))
				return w
			}
			base := engine.Current()
			next := *base
			next.System.Hostname = "pending-router"
			next.System.Panel.CommitTimeout = 15
			version := s.draftVersion
			if private {
				d := s.privateDraftLocked("admin")
				d.Config = &next
				version = d.Version
			} else {
				s.draft = &next
			}
			if w := request(version); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			first, err := s.Store.LatestRevision()
			if err != nil {
				t.Fatal(err)
			}
			rollback := make(chan error, 1)
			go func() { rollback <- engine.Rollback(context.Background()) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("rollback callback did not run")
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- request(version) }()
			deadline := time.Now().Add(5 * time.Second)
			var queued bool
			for time.Now().Before(deadline) {
				latest, err := s.Store.LatestRevision()
				if err == nil && latest.ID > first.ID && latest.State == store.StateApplying {
					queued = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			unblock()
			if err := <-rollback; err != nil {
				t.Fatal(err)
			}
			w := <-done
			if !queued || w.Code != 409 || engine.Current() != base || len(sub.applied) != 3 || engine.LastRollback() == nil {
				t.Fatalf("queued=%v status=%d restored=%v applies=%v notice=%v", queued, w.Code, engine.Current() == base, sub.applied, engine.LastRollback())
			}
			latest, err := s.Store.LatestRevision()
			if err != nil || latest.State != store.StateFailed {
				t.Fatalf("stale revision: %+v %v", latest, err)
			}
			original, err := s.Store.Revision(first.ID)
			if err != nil || original.State != store.StateRolledBack {
				t.Fatalf("original revision: %+v %v", original, err)
			}
			version = s.draftVersion
			if private {
				version = s.privateDraftLocked("admin").Version
			}
			if w := request(version); w.Code != 200 {
				t.Fatalf("fresh retry: %s", w.Body.String())
			}
		})
	}
}
