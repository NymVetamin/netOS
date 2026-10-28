package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/netos-router/netos/internal/certificates"
	"github.com/netos-router/netos/internal/config"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPanelHTTPSRedirect(t *testing.T) {
	head := httptest.NewRecorder()
	panelHTTPSRedirect(443).ServeHTTP(head, httptest.NewRequest(http.MethodHead, "http://router.test/", nil))
	if head.Code != 302 || head.Body.Len() != 0 {
		t.Fatal("HEAD redirect changed")
	}
	for _, tc := range []struct {
		host, path, want string
		port             int
	}{
		{"router.test:80", "/clients?a=1", "https://router.test:8443/clients?a=1", 8443},
		{"192.0.2.1", "/", "https://192.0.2.1/", 443},
		{"[2001:db8::1]:80", "/a%2Fb?q=a%20b", "https://[2001:db8::1]:9443/a%2Fb?q=a%20b", 9443},
		{"[::1]", "//elsewhere.test/path", "https://[::1]//elsewhere.test/path", 443},
	} {
		r := httptest.NewRequest("GET", "http://local"+tc.path, nil)
		r.Host = tc.host
		r.Header.Set("X-Forwarded-Host", "evil.test")
		w := httptest.NewRecorder()
		panelHTTPSRedirect(tc.port).ServeHTTP(w, r)
		if w.Code != 302 || w.Header().Get("Location") != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%+v: %d %v", tc, w.Code, w.Header())
		}
	}
	for _, host := range []string{"", "user@router.test", "router.test/evil", "router.test?x", "router.test#x", "router.test\\evil", "router.test:bad", "router.test:80:90"} {
		r := httptest.NewRequest("GET", "http://local/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		panelHTTPSRedirect(443).ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("host %q accepted: %d", host, w.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		r := httptest.NewRequest(method, "http://local/api/login", strings.NewReader(`{"password":"secret"}`))
		w := httptest.NewRecorder()
		panelHTTPSRedirect(443).ServeHTTP(w, r)
		if w.Code != 405 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("plaintext %s: %d", method, w.Code)
		}
	}
}

func TestPanelMaintenanceCanReuseOwnHTTPPort(t *testing.T) {
	previous := panelPortAvailable
	panelPortAvailable = func(int) error { return fmt.Errorf("address in use") }
	defer func() { panelPortAvailable = previous }()
	for _, owned := range []bool{false, true} {
		s, cookie, csrf := newAuthedServer(t)
		cfg := initializeAPIEngine(t, s)
		id, err := s.Store.CreateRevision(cfg, "system", "active")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Store.MarkActive(id); err != nil {
			t.Fatal(err)
		}
		s.Maintenance = &Maintenance{Runner: &maintenanceRouteRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
		if owned {
			s.challengeServer = &http.Server{}
		}
		w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/panel", []byte(`{"panel":{"port":80,"commit_timeout":30,"tls":{"mode":"selfsigned"}},"confirm":"RESTART"}`), cookie, csrf)
		want := http.StatusConflict
		if owned {
			want = http.StatusAccepted
		}
		if w.Code != want {
			t.Fatalf("owned=%v status=%d body=%s", owned, w.Code, w.Body.String())
		}
	}
}

func TestPanelHTTPRedirectLifecycle(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, occupied := range []bool{false, true} {
			t.Run(fmt.Sprintf("managed=%v/occupied=%v", managed, occupied), func(t *testing.T) {
				cfg := config.Default()
				cfg.System.Panel.Port = freeTCPPort(t)
				address := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
				var blocker net.Listener
				if occupied {
					var err error
					blocker, err = net.Listen("tcp", address)
					if err != nil {
						t.Fatal(err)
					}
					defer blocker.Close()
				}
				logger := &lifecycleLogger{}
				s := New(nil, nil, nil, logger)
				s.ACMEHTTPAddress = address
				if managed {
					s.Certificates = certificates.New(t.TempDir(), nil)
					s.Certificates.HTTPAddress = address
					defer s.Certificates.Close()
				}
				ready := make(chan struct{})
				s.Ready = func() error { close(ready); return nil }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				dir := t.TempDir()
				go func() { done <- s.Start(ctx, cfg, dir) }()
				select {
				case <-ready:
				case err := <-done:
					t.Fatalf("Start: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("not ready")
				}
				client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				if occupied {
					if !strings.Contains(logger.String(), "HTTP-переход на HTTPS недоступен") {
						t.Fatal("missing warning")
					}
				} else {
					resp, err := client.Get("http://" + address + "/api/ping?check=1")
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					want := fmt.Sprintf("https://127.0.0.1:%d/api/ping?check=1", cfg.System.Panel.Port)
					if resp.StatusCode != 302 || resp.Header.Get("Location") != want {
						t.Fatalf("redirect: %d %v", resp.StatusCode, resp.Header)
					}
					resp, err = client.Post("http://"+address+"/api/login", "application/json", strings.NewReader(`{}`))
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					if resp.StatusCode != 405 {
						t.Fatal(resp.StatusCode)
					}
				}
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // local generated test certificate
				resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/ping", cfg.System.Panel.Port))
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				client.CloseIdleConnections()
				if resp.StatusCode != 200 {
					t.Fatal(resp.StatusCode)
				}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown stuck")
				}
				if managed {
					s.Certificates.Close()
				}
				if !occupied {
					ln, err := net.Listen("tcp", address)
					if err != nil {
						t.Fatalf("HTTP port leaked: %v", err)
					}
					ln.Close()
				}
			})
		}
	}
}
