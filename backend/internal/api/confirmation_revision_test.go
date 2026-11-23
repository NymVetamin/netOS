package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/store"
)

func TestConfirmationBoundToDisplayedRevision(t *testing.T) {
	for _, action := range []string{"confirm", "rollback"} {
		t.Run(action, func(t *testing.T) {
			s, cookie, csrf, _ := transactionServer(t)
			h := s.Routes()
			request := func(action string, rev int64) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/api/config/"+action, nil)
				req.AddCookie(cookie)
				req.Header.Set(csrfHeader, csrf)
				req.Header.Set("If-Match", strconv.FormatInt(rev, 10))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				return w
			}
			readShown := func(want int64) {
				t.Helper()
				w := serveAuthed(h, http.MethodGet, "/api/config", nil, cookie, csrf)
				var snapshot struct {
					Pending  bool   `json:"pending_confirmation"`
					Revision string `json:"pending_revision"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || w.Code != 200 {
					t.Fatalf("config status=%d err=%v", w.Code, err)
				}
				if want == 0 {
					if snapshot.Pending || snapshot.Revision != "" {
						t.Fatalf("unexpected pending: %+v", snapshot)
					}
				} else if !snapshot.Pending || snapshot.Revision != strconv.FormatInt(want, 10) {
					t.Fatalf("wrong pending: %+v", snapshot)
				}
			}
			first := applyDraft(t, s, cookie, csrf, "router-one")
			readShown(first)
			if w := request("confirm", first); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			second := applyDraft(t, s, cookie, csrf, "router-two")
			defer s.Engine.Confirm(nil)
			readShown(second)
			if w := request(action, first); w.Code != 409 {
				rev, err := s.Store.Revision(second)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("stale %s(%d): status %d, revision %d state %s, current %s", action, first, w.Code, second, rev.State, s.Engine.Current().System.Hostname)
			}
			if pending, _ := s.Engine.Pending(); !pending || s.Engine.Current().System.Hostname != "router-two" {
				t.Fatal("stale request changed pending revision")
			}
			if w := request(action, second); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			readShown(0)
			if w := request(action, second); w.Code != 409 {
				t.Fatalf("repeat status %d", w.Code)
			}
			want := store.StateActive
			if action == "rollback" {
				want = store.StateRolledBack
			}
			rev, err := s.Store.Revision(second)
			if err != nil || rev.State != want {
				t.Fatalf("revision %+v, err %v", rev, err)
			}
		})
	}
}
