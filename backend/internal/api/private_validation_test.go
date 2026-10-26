package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestPrivateSaveRetainsWarningsAndRejectsInvalidChanges(t *testing.T) {
	s, _, _, _ := transactionServer(t)
	call := func(method string, cfg *config.Config, version uint64) *httptest.ResponseRecorder {
		body, _ := json.Marshal(cfg)
		r := httptest.NewRequest(method, "/api/config", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, "admin"))
		r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
		r.Header.Set("If-Match", strconv.FormatUint(version, 10))
		w := httptest.NewRecorder()
		s.handlePrivateConfig(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder) configResponse {
		t.Helper()
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result configResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	initial := decode(call("GET", nil, 0))
	cfg := initial.Config
	cfg.Firewall.Enabled = false
	cfg.Clients = []config.Client{{ID: "blocked", MAC: "02:00:00:00:00:01", Blocked: true}}
	saved := decode(call("PUT", cfg, initial.DraftVersion))
	if len(saved.Problems) == 0 {
		t.Fatal("warning fixture produced no warnings")
	}
	read := decode(call("GET", nil, 0))
	if !reflect.DeepEqual(saved.Problems, read.Problems) {
		t.Fatal("PUT lost or changed warnings", saved.Problems, read.Problems)
	}
	cfg.Clients[0].MAC = "invalid"
	failed := call("PUT", cfg, saved.DraftVersion)
	if failed.Code != 422 {
		t.Fatal("invalid configuration accepted", failed.Code, failed.Body.String())
	}
	var response errorResponse
	if err := json.Unmarshal(failed.Body.Bytes(), &response); err != nil || len(response.Problems) == 0 {
		t.Fatal("missing validation errors", err)
	}
	after := decode(call("GET", nil, 0))
	if after.DraftVersion != saved.DraftVersion || !sameConfig(after.Config, read.Config) {
		t.Fatal("invalid PUT changed the draft")
	}
}
