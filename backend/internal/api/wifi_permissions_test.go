package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

type wifiUnavailableRunner struct{ calls int }

func (r *wifiUnavailableRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", errors.New("hardware unavailable")
}
func (r *wifiUnavailableRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestWiFiHardwarePermissions(t *testing.T) {
	for _, section := range []string{"wifi", "network", "system"} {
		for _, level := range []string{"", "view", "manage"} {
			for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
				r := limitedRequest(map[string]string{section: level})
				r.URL.Path, r.Method = "/api/wifi/hardware", method
				want := method == "GET" && section == "wifi" && level != ""
				if limitedEndpoint(r) != want {
					t.Errorf("%s %s=%s: want allowed=%v", method, section, level, want)
				}
			}
		}
	}
}

func TestWiFiHardwareAuthenticatedRoutes(t *testing.T) {
	s, adminCookie, _ := newAuthedServer(t)
	runner := &wifiUnavailableRunner{}
	s.StorageRunner = runner
	h := s.Routes()
	for _, tc := range []struct {
		name, section, level string
		enabled              bool
		want                 int
	}{
		{"read", "wifi", "view", true, 503},
		{"manage", "wifi", "manage", true, 503},
		{"none", "wifi", "", true, 403},
		{"network", "network", "manage", true, 403},
		{"disabled", "wifi", "manage", false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := store.PanelUser{Username: tc.name, Role: "limited", PanelAccess: store.PanelAccess{Enabled: tc.enabled, Permissions: map[string]string{tc.section: tc.level}}}
			if err := s.Store.SavePanelUser(u, "hash", true, false, "admin", "test"); err != nil {
				t.Fatal(err)
			}
			token := "wifi-test-" + tc.name
			if _, err := s.Store.CreateSession(token, tc.name, "test", time.Hour); err != nil {
				t.Fatal(err)
			}
			cookie := &http.Cookie{Name: sessionCookie, Value: token}
			for attempt := 0; attempt < 2; attempt++ {
				before := runner.calls
				w := serveAuthed(h, "GET", "/api/wifi/hardware?country=US", nil, cookie, "")
				if w.Code != tc.want {
					t.Fatalf("%d: %s", w.Code, w.Body.String())
				}
				if (runner.calls > before) != (tc.want == 503) {
					t.Fatal("discovery executed outside permitted request")
				}
			}
		})
	}
	if w := serveAuthed(h, "GET", "/api/wifi/hardware", nil, nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := serveAuthed(h, "GET", "/api/wifi/hardware", nil, adminCookie, ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
}
