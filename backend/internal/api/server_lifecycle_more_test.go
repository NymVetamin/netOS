package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/tlsutil"
)

type lifecycleLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *lifecycleLogger) add(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *lifecycleLogger) Infof(format string, args ...any)  { l.add(format, args...) }
func (l *lifecycleLogger) Warnf(format string, args ...any)  { l.add(format, args...) }
func (l *lifecycleLogger) Errorf(format string, args ...any) { l.add(format, args...) }
func (l *lifecycleLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func runTLSServer(t *testing.T, cfg *config.Config, tlsDir string) (*http.Response, string) {
	t.Helper()
	logger := &lifecycleLogger{}
	s := New(nil, nil, nil, logger)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, cfg, tlsDir) }()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- local test server
		Timeout:   250 * time.Millisecond,
	}
	var resp *http.Response
	var err error
	url := fmt.Sprintf("https://127.0.0.1:%d/api/ping", cfg.System.Panel.Port)
	for i := 0; i < 50; i++ {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		select {
		case startErr := <-done:
			t.Fatalf("TLS request failed: %v; Start=%v; logs=%s", err, startErr, logger.String())
		case <-time.After(2 * time.Second):
			t.Fatalf("TLS request failed and Start did not stop: %v", err)
		}
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) {
		cancel()
		t.Fatalf("response status=%d body=%q err=%v", resp.StatusCode, body, readErr)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		cancel()
		t.Fatalf("negotiated TLS state=%+v", resp.TLS)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not stop after context cancellation")
	}
	return resp, logger.String()
}

func TestStartServesTLSAndShutsDown(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	tlsDir := t.TempDir()
	resp, logs := runTLSServer(t, cfg, tlsDir)
	if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers=%v", resp.Header)
	}
	for _, name := range []string{"panel.crt", "panel.key"} {
		if _, err := os.Stat(filepath.Join(tlsDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if !strings.Contains(logs, "отпечаток") || !strings.Contains(logs, "панель доступна") {
		t.Fatalf("startup logs=%s", logs)
	}
}

func TestStartCustomTLSUsesAndReportsActualCertificate(t *testing.T) {
	customDir := t.TempDir()
	cert, key, fingerprint, err := tlsutil.EnsureSelfSigned(customDir, "custom.test")
	if err != nil {
		t.Fatal(err)
	}
	blockedTLSDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedTLSDir, []byte("must remain untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "custom", CertFile: cert, KeyFile: key}
	_, logs := runTLSServer(t, cfg, blockedTLSDir)
	if !strings.Contains(logs, fingerprint) {
		t.Fatalf("actual custom fingerprint %q absent from logs: %s", fingerprint, logs)
	}
	data, err := os.ReadFile(blockedTLSDir)
	if err != nil || string(data) != "must remain untouched" {
		t.Fatalf("custom mode mutated self-signed directory marker: %q, %v", data, err)
	}
}

func TestCustomTLSRejectsMismatchedPairBeforeListening(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	certA, _, _, err := tlsutil.EnsureSelfSigned(dirA, "a.test")
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, _, err := tlsutil.EnsureSelfSigned(dirB, "b.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "custom", CertFile: certA, KeyFile: keyB}
	logger := &lifecycleLogger{}
	err = New(nil, nil, nil, logger).Start(context.Background(), cfg, filepath.Join(t.TempDir(), "unused"))
	if err == nil || !strings.Contains(err.Error(), "пользовательского сертификата") {
		t.Fatalf("mismatched custom pair error=%v", err)
	}
}

func TestReadyCallbackRunsAfterLiveAPIAndFailureClosesListener(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	s := New(nil, nil, nil, &lifecycleLogger{})
	called := false
	s.Ready = func() error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second} // #nosec G402 -- loopback readiness test
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/ping", cfg.System.Panel.Port))
		if err != nil {
			return fmt.Errorf("API was not live in Ready callback: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("API status in Ready callback: %d", resp.StatusCode)
		}
		called = true
		return fmt.Errorf("injected marker write failure")
	}
	err := s.Start(context.Background(), cfg, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "marker write failure") || !called {
		t.Fatalf("Start error=%v called=%v", err, called)
	}
	ln, listenErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.System.Panel.Port))
	if listenErr != nil {
		t.Fatalf("panel listener leaked after Ready failure: %v", listenErr)
	}
	_ = ln.Close()
}

func TestPruneOnceRemovesExpiredSessionAndCSRFState(t *testing.T) {
	s, _, _ := newAuthedServer(t)
	logger := &lifecycleLogger{}
	s.Logger = logger
	if _, err := s.Store.CreateSession("expired-token", "admin", "127.0.0.2", -time.Minute); err != nil {
		t.Fatal(err)
	}
	s.csrfTokens["expired-token"] = "expired-csrf"
	s.loginFails["stale"] = &failCounter{last: time.Now().Add(-loginFailureTTL - time.Minute)}
	s.pruneOnce()
	if _, ok := s.csrfTokens["expired-token"]; ok {
		t.Fatal("expired CSRF token survived session pruning")
	}
	if _, ok := s.loginFails["stale"]; ok {
		t.Fatal("stale login failure survived pruning")
	}
	if _, err := s.Store.SessionUser("session-token"); err != nil {
		t.Fatalf("live session was pruned: %v", err)
	}

	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s.pruneOnce()
	if !strings.Contains(logger.String(), "уборка сессий") || !strings.Contains(logger.String(), "уборка ревизий") || !strings.Contains(logger.String(), "уборка журнала аудита") {
		t.Fatalf("prune errors not logged: %s", logger.String())
	}
}

func TestNewAndLogWriter(t *testing.T) {
	logger := &lifecycleLogger{}
	s := New(nil, nil, nil, logger)
	if s.draftVersion != 1 || s.csrfTokens == nil || s.loginFails == nil || cap(s.loginSlots) != maxConcurrentLogins {
		t.Fatalf("New fields=%+v", s)
	}
	message := "  transport warning  \n"
	n, err := (logWriter{logger}).Write([]byte(message))
	if err != nil || n != len(message) || !strings.Contains(logger.String(), "transport warning") {
		t.Fatalf("log writer n=%d err=%v logs=%s", n, err, logger.String())
	}
}
