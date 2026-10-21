package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestAdministratorsHaveIndependentDrafts(t *testing.T) {
	s, _, _, _ := transactionServer(t)
	request := func(user, method, path string, cfg *config.Config, version uint64) *httptest.ResponseRecorder {
		body, _ := json.Marshal(cfg)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, user))
		r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
		r.Header.Set("If-Match", strconv.FormatUint(version, 10))
		w := httptest.NewRecorder()
		switch method {
		case "GET":
			s.handleGetConfig(w, r)
		case "PUT":
			s.handleSaveConfig(w, r)
		default:
			s.handleDiscard(w, r)
		}
		return w
	}
	get := func(user string) configResponse {
		w := request(user, "GET", "/api/config", nil, 0)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var out configResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b := get("alice"), get("bob")
	a.Config.System.Hostname = "alice-router"
	if w := request("alice", "PUT", "/api/config", a.Config, a.DraftVersion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if got := get("bob"); got.Dirty || got.Config.System.Hostname == "alice-router" {
		t.Fatal("another administrator sees Alice's draft")
	}
	b.Config.System.Hostname = "bob-router"
	if w := request("bob", "PUT", "/api/config", b.Config, b.DraftVersion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request("alice", "PUT", "/api/config", a.Config, a.DraftVersion); w.Code != 409 {
		t.Fatal("stale same-user edit accepted")
	}
	a = get("alice")
	if w := request("alice", "POST", "/api/config/discard", nil, a.DraftVersion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if got := get("bob"); !got.Dirty || got.Config.System.Hostname != "bob-router" {
		t.Fatal("discard changed another user's draft")
	}
	revisionConfig := *s.Engine.Current()
	revisionConfig.System.Hostname = "restored-alice"
	id, err := s.Store.CreateRevision(&revisionConfig, "alice", "restore isolation")
	if err != nil {
		t.Fatal(err)
	}
	a = get("alice")
	r := httptest.NewRequest("POST", "/api/revisions/restore", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, "alice"))
	r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.Header.Set("If-Match", strconv.FormatUint(a.DraftVersion, 10))
	w := httptest.NewRecorder()
	s.handleRestoreRevision(w, r)
	if w.Code != 200 || get("alice").Config.System.Hostname != "restored-alice" || get("bob").Config.System.Hostname != "bob-router" {
		t.Fatal("revision restore crossed user drafts", w.Body.String())
	}
	// Once the active configuration changes, an old draft must never overwrite it.
	next := *s.Engine.Current()
	next.System.Hostname = "applied-by-alice"
	if _, err := s.Engine.Apply(context.Background(), &next, 0, false); err != nil {
		t.Fatal(err)
	}
	b = get("bob")
	if !b.Dirty || b.Config.System.Hostname != "bob-router" {
		t.Fatal("stale draft lost")
	}
	if w := request("bob", "PUT", "/api/config", b.Config, b.DraftVersion); w.Code != 409 {
		t.Fatal("stale baseline accepted")
	}
	if w := request("bob", "POST", "/api/config/discard", nil, b.DraftVersion); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if got := get("bob"); got.Dirty || got.Config.System.Hostname != "applied-by-alice" {
		t.Fatal("discard did not reload active config")
	}
}
