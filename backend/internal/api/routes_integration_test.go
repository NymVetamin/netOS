package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func initializeAPIEngine(t *testing.T, s *Server) *config.Config {
	t.Helper()
	cfg := config.Default()
	s.Engine = apply.NewEngine(nil, true)
	if _, err := s.Engine.Apply(context.Background(), cfg, 1, false); err != nil {
		t.Fatal(err)
	}
	if s.draftVersion == 0 {
		s.draftVersion = 1
	}
	return cfg
}

func serveAuthed(handler http.Handler, method, path string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestRoutesEnforceAuthenticationRolesCSRFAndFallbacks(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthedServer(t)
	initializeAPIEngine(t, s)
	h := s.Routes()

	if w := serveAuthed(h, http.MethodGet, "/api/config", nil, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated config status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodPut, "/api/config", []byte(`{}`), adminCookie, "wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodGet, "/api/config", nil, adminCookie, ""); w.Code != http.StatusOK {
		t.Fatalf("admin config status=%d body=%s", w.Code, w.Body.String())
	}

	viewerHash, err := HashPassword("viewer-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateUser("viewer", viewerHash, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateSession("viewer-session", "viewer", "127.0.0.2", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["viewer-session"] = "viewer-csrf"
	viewerCookie := &http.Cookie{Name: sessionCookie, Value: "viewer-session"}
	if w := serveAuthed(h, http.MethodGet, "/api/config", nil, viewerCookie, ""); w.Code != http.StatusOK {
		t.Fatalf("viewer read status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodPut, "/api/config", []byte(`{}`), viewerCookie, "viewer-csrf"); w.Code != http.StatusForbidden {
		t.Fatalf("viewer mutation status=%d body=%s", w.Code, w.Body.String())
	}

	if w := serveAuthed(h, http.MethodGet, "/api/does-not-exist", nil, adminCookie, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown API status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodPost, "/", nil, nil, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("SPA mutation status=%d", w.Code)
	}
	if w := serveAuthed(h, http.MethodGet, "/deep/client/route", nil, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("SPA fallback status=%d body=%s", w.Code, w.Body.String())
	}

	w := serveAuthed(h, http.MethodPost, "/api/logout", nil, adminCookie, adminCSRF)
	if w.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := s.Store.SessionUser(adminCookie.Value); err == nil {
		t.Fatal("logout left session valid")
	}
	if w := serveAuthed(h, http.MethodGet, "/api/session", nil, adminCookie, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session status=%d", w.Code)
	}
}

func TestReadOnlyRoutesAndKeypairHandlers(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	initializeAPIEngine(t, s)
	h := s.Routes()

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/ping", http.StatusOK},
		{"/api/session", http.StatusOK},
		{"/api/catalog", http.StatusOK},
		{"/api/ddns/status", http.StatusOK},
		{"/api/statistics?hours=168", http.StatusOK},
		{"/api/maintenance/status", http.StatusOK},
		{"/api/backups", http.StatusServiceUnavailable},
		{"/api/revisions?limit=5", http.StatusOK},
		{"/api/audit?limit=5", http.StatusOK},
		{"/api/render", http.StatusOK},
		{"/api/render/iptables", http.StatusOK},
		{"/api/render/not-real", http.StatusNotFound},
		{"/api/revisions/not-a-number", http.StatusBadRequest},
		{"/api/revisions/999999", http.StatusNotFound},
		{"/api/vpn-servers/missing/certificate", http.StatusNotFound},
	} {
		t.Run(strings.ReplaceAll(tc.path, "/", "_"), func(t *testing.T) {
			w := serveAuthed(h, http.MethodGet, tc.path, nil, cookie, "")
			if w.Code != tc.want {
				t.Fatalf("GET %s status=%d want=%d body=%s", tc.path, w.Code, tc.want, w.Body.String())
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("GET %s Cache-Control=%q", tc.path, got)
			}
		})
	}

	generated := serveAuthed(h, http.MethodPost, "/api/xray/keypair", []byte(`{}`), cookie, csrf)
	if generated.Code != http.StatusOK {
		t.Fatalf("generate xray keypair status=%d body=%s", generated.Code, generated.Body.String())
	}
	var pair map[string]string
	if err := json.Unmarshal(generated.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	deriveBody, _ := json.Marshal(map[string]string{"private_key": pair["private_key"]})
	derived := serveAuthed(h, http.MethodPost, "/api/xray/keypair", deriveBody, cookie, csrf)
	if derived.Code != http.StatusOK || !strings.Contains(derived.Body.String(), pair["public_key"]) {
		t.Fatalf("derive xray keypair status=%d body=%s", derived.Code, derived.Body.String())
	}
	invalid := serveAuthed(h, http.MethodPost, "/api/xray/keypair", []byte(`{"private_key":"bad"}`), cookie, csrf)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid xray key status=%d body=%s", invalid.Code, invalid.Body.String())
	}
}

type catalogComponentProbe struct {
	installed map[string]bool
	running   map[string]bool
}

func (p catalogComponentProbe) Status(context.Context) map[string]bool  { return p.installed }
func (p catalogComponentProbe) Running(context.Context) map[string]bool { return p.running }

func TestCatalogReturnsMetadataAndIndependentLiveStates(t *testing.T) {
	s, cookie, _ := newAuthedServer(t)
	initializeAPIEngine(t, s)
	s.Components = catalogComponentProbe{
		installed: map[string]bool{"dnsmasq": true, "xray": false},
		running:   map[string]bool{"dnsmasq": false, "xray": true},
	}
	w := serveAuthed(s.Routes(), http.MethodGet, "/api/catalog", nil, cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Components []config.ComponentInfo `json:"components"`
		Installed  map[string]bool        `json:"installed"`
		Running    map[string]bool        `json:"running"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Components) != len(config.Catalog) {
		t.Fatalf("catalog length=%d want=%d", len(response.Components), len(config.Catalog))
	}
	if !response.Installed["dnsmasq"] || response.Installed["xray"] {
		t.Fatalf("installed state=%v", response.Installed)
	}
	if response.Running["dnsmasq"] || !response.Running["xray"] {
		t.Fatalf("running state=%v", response.Running)
	}
	var sawEssential, sawExternal bool
	for _, item := range response.Components {
		sawEssential = sawEssential || item.Essential
		sawExternal = sawExternal || item.External
	}
	if !sawEssential || !sawExternal {
		t.Fatalf("catalog lost metadata: essential=%v external=%v", sawEssential, sawExternal)
	}
}

func TestConfigurationRouteLifecycle(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	base := initializeAPIEngine(t, s)
	h := s.Routes()

	changed := *base
	changed.System.Hostname = "route-lifecycle"
	body, err := json.Marshal(&changed)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("If-Match", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", w.Code, w.Body.String())
	}
	var saved configResponse
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Dirty || saved.DraftVersion != 2 {
		t.Fatalf("unexpected saved draft: %+v", saved)
	}

	if w := serveAuthed(h, http.MethodPost, "/api/config/plan", nil, cookie, csrf); w.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", w.Code, w.Body.String())
	}
	if w := serveAuthed(h, http.MethodPost, "/api/config/validate", body, cookie, csrf); w.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", w.Code, w.Body.String())
	}
	applyBody := []byte(`{"comment":"route lifecycle","draft_version":2}`)
	if w := serveAuthed(h, http.MethodPost, "/api/config/apply", applyBody, cookie, csrf); w.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", w.Code, w.Body.String())
	}
	if got := s.Engine.Current().System.Hostname; got != "route-lifecycle" {
		t.Fatalf("applied hostname=%q", got)
	}
	revisions, err := s.Store.ListRevisions(10)
	if err != nil || len(revisions) != 1 || revisions[0].State != "active" {
		t.Fatalf("revisions=%+v err=%v", revisions, err)
	}

	revisionPath := "/api/revisions/" + strconv.FormatInt(revisions[0].ID, 10)
	if w := serveAuthed(h, http.MethodGet, revisionPath, nil, cookie, ""); w.Code != http.StatusOK {
		t.Fatalf("revision status=%d body=%s", w.Code, w.Body.String())
	}
	restoreReq := httptest.NewRequest(http.MethodPost, revisionPath+"/restore", nil)
	restoreReq.AddCookie(cookie)
	restoreReq.Header.Set(csrfHeader, csrf)
	restoreReq.Header.Set("If-Match", "3")
	restoreW := httptest.NewRecorder()
	h.ServeHTTP(restoreW, restoreReq)
	if restoreW.Code != http.StatusOK {
		t.Fatalf("restore revision status=%d body=%s", restoreW.Code, restoreW.Body.String())
	}

	discardReq := httptest.NewRequest(http.MethodPost, "/api/config/discard", nil)
	discardReq.AddCookie(cookie)
	discardReq.Header.Set(csrfHeader, csrf)
	discardReq.Header.Set("If-Match", "4")
	discardW := httptest.NewRecorder()
	h.ServeHTTP(discardW, discardReq)
	if discardW.Code != http.StatusOK {
		t.Fatalf("discard status=%d body=%s", discardW.Code, discardW.Body.String())
	}
	for _, path := range []string{"/api/config/confirm", "/api/config/rollback"} {
		if w := serveAuthed(h, http.MethodPost, path, nil, cookie, csrf); w.Code != http.StatusConflict {
			t.Fatalf("%s without pending operation status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
}

func TestReadJSONRejectsTrailingAndOversizedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"trailing value", `{}` + ` {}`},
		{"oversized", `{"value":"` + strings.Repeat("x", (8<<20)+1) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var value map[string]any
			if err := readJSON(req, &value); err == nil {
				t.Fatal("invalid request body was accepted")
			}
		})
	}
}
