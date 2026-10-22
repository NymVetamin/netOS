package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalControlPersonalDrafts(t *testing.T) {
	s, _, _, subsystem := transactionServer(t)
	h := s.localControlHandler()
	request := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		if w.Code != status {
			t.Fatalf("%s %s: status=%d body=%s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	seed := func(owner, hostname string) {
		s.draftMu.Lock()
		defer s.draftMu.Unlock()
		cfg := *s.Engine.Current()
		cfg.System.Hostname = hostname
		d := s.privateDraftLocked(owner)
		d.Config = &cfg
		d.Version++
	}
	if w := request("GET", "/draft", "", 200); !strings.Contains(w.Body.String(), `"dirty":false`) {
		t.Fatal(w.Body.String())
	}
	request("POST", "/apply", `{"draft_version":1}`, 409)
	request("GET", "/draft?user=missing", "", 409)
	seed("alice", "alice-router")
	var selected struct {
		Owner   string `json:"owner"`
		Version uint64 `json:"draft_version"`
	}
	if err := json.Unmarshal(request("GET", "/draft", "", 200).Body.Bytes(), &selected); err != nil || selected.Owner != "alice" {
		t.Fatal("sole draft was not selected", selected, err)
	}
	body, _ := json.Marshal(map[string]any{"draft_version": selected.Version})
	// Bob appears after the CLI has read Alice's version. A pinned request
	// must still apply Alice; an ambiguous unqualified request must fail.
	seed("bob", "bob-router")
	request("GET", "/draft", "", 409)
	request("POST", "/apply", string(body), 409)
	request("GET", "/draft?user=bob", "", 200)
	request("POST", "/apply?user=alice", `{"draft_version":0}`, 409)
	if s.Engine.Current().System.Hostname == "alice-router" {
		t.Fatal("stale apply changed configuration")
	}
	subsystem.planErr = true
	request("POST", "/apply?user=alice", string(body), 500)
	if s.privateDrafts["alice"].Config == nil {
		t.Fatal("failed apply lost draft")
	}
	subsystem.planErr = false
	request("POST", "/apply?user=alice", string(body), 200)
	if s.Engine.Current().System.Hostname != "alice-router" || s.pendingOwner != "alice" {
		t.Fatal("wrong personal draft applied")
	}
	request("POST", "/confirm", `{}`, 200)
	if s.privateDrafts["alice"].Config != nil || s.privateDrafts["bob"].Config == nil {
		t.Fatal("confirm cleared the wrong draft")
	}
	request("POST", "/confirm", `{}`, 409)
	// Bob's version is current but his baseline predates Alice's apply.
	bobBody, _ := json.Marshal(map[string]any{"draft_version": s.privateDrafts["bob"].Version})
	request("POST", "/apply?user=bob", string(bobBody), 409)
	if s.Engine.Current().System.Hostname != "alice-router" {
		t.Fatal("stale baseline overwrote applied configuration")
	}
}

func TestLocalRootConfirmsPanelApply(t *testing.T) {
	s, cookie, csrf, _ := transactionServer(t)
	applyDraft(t, s, cookie, csrf, "panel-change")
	w := httptest.NewRecorder()
	s.localControlHandler().ServeHTTP(w, httptest.NewRequest("POST", "/confirm", strings.NewReader(`{}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if pending, _ := s.Engine.Pending(); pending || s.privateDrafts["admin"].Config != nil {
		t.Fatal("root did not confirm and clear panel draft")
	}
}
