package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/tlsutil"
)

type fakeACMEManager struct {
	mu        sync.Mutex
	cert      tls.Certificate
	requested []string
	issueErr  error
	block     <-chan struct{}
}

func newFakeACMEManager(t *testing.T) *fakeACMEManager {
	t.Helper()
	certPath, keyPath, _, err := tlsutil.EnsureSelfSigned(t.TempDir(), "router.acme-valid.com")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeACMEManager{cert: pair}
}

func (m *fakeACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requested = append(m.requested, hello.ServerName)
	block := m.block
	m.mu.Unlock()
	if block != nil {
		<-block
	}
	m.mu.Lock()
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	cert := m.cert
	return &cert, nil
}

func TestACMEIssuanceHonorsDaemonCancellation(t *testing.T) {
	manager := newFakeACMEManager(t)
	blocked := make(chan struct{})
	manager.block = blocked
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.acme-valid.com", AcceptTOS: true}
	s := New(nil, nil, nil, &lifecycleLogger{})
	s.ACMEHTTPAddress = "127.0.0.1:0"
	s.ACMEFactory = func(_, _, _ string) (acmeCertificateManager, error) { return manager, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, cfg, t.TempDir()) }()
	for i := 0; i < 100; i++ {
		manager.mu.Lock()
		started := len(manager.requested) > 0
		manager.mu.Unlock()
		if started {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("cancel error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ACME issuance ignored daemon cancellation")
	}
	close(blocked)
}

func (m *fakeACMEManager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("challenge"))
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

func (m *fakeACMEManager) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.GetCertificate}
}

func TestACMEPanelIssuesBeforeReadyAndServesTLS(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "Router.ACME-VALID.COM.", Email: "admin@example.org", AcceptTOS: true}
	manager := newFakeACMEManager(t)
	logger := &lifecycleLogger{}
	s := New(nil, nil, nil, logger)
	s.ACMEHTTPAddress = "127.0.0.1:0"
	s.ACMECheckInterval = 10 * time.Millisecond
	var factoryCache, factoryDomain, factoryEmail string
	s.ACMEFactory = func(cache, domain, email string) (acmeCertificateManager, error) {
		factoryCache, factoryDomain, factoryEmail = cache, domain, email
		return manager, nil
	}
	ready := make(chan struct{}, 1)
	s.Ready = func() error { ready <- struct{}{}; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, cfg, t.TempDir()) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Start before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("ACME panel never became ready")
	}
	manager.mu.Lock()
	requests := append([]string(nil), manager.requested...)
	manager.mu.Unlock()
	if len(requests) == 0 || requests[0] != "router.acme-valid.com" {
		t.Fatalf("prefetch requests=%v", requests)
	}
	if factoryDomain != cfg.System.Panel.TLS.Domain || factoryEmail != cfg.System.Panel.TLS.Email || filepath.Base(filepath.Dir(factoryCache)) != "acme" {
		t.Fatalf("factory cache=%q domain=%q email=%q", factoryCache, factoryDomain, factoryEmail)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, ServerName: "router.acme-valid.com", // #nosec G402 -- local fake CA test
	}}, Timeout: time.Second}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/ping", cfg.System.Panel.Port))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("ACME HTTPS status=%v err=%v", func() any {
			if resp != nil {
				return resp.StatusCode
			}
			return nil
		}(), err)
	}
	firstCert := append([]byte(nil), resp.TLS.PeerCertificates[0].Raw...)
	_ = resp.Body.Close()
	client.CloseIdleConnections()
	renewed := newFakeACMEManager(t)
	manager.mu.Lock()
	manager.cert = renewed.cert
	manager.mu.Unlock()
	var renewedCertServed bool
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, ServerName: "router.acme-valid.com", // #nosec G402 -- local fake CA test
		}}
		probe := &http.Client{Transport: transport, Timeout: time.Second}
		resp, err = probe.Get(fmt.Sprintf("https://127.0.0.1:%d/api/ping", cfg.System.Panel.Port))
		if err == nil && resp.StatusCode == http.StatusOK && string(resp.TLS.PeerCertificates[0].Raw) != string(firstCert) {
			renewedCertServed = true
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		transport.CloseIdleConnections()
		if renewedCertServed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !renewedCertServed {
		t.Fatalf("renewed certificate was not served: status=%v err=%v", func() any {
			if resp != nil {
				return resp.StatusCode
			}
			return nil
		}(), err)
	}
	for i := 0; i < 100 && !strings.Contains(logger.String(), "сертификат ACME обновлён"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logger.String(), "сертификат ACME обновлён") {
		t.Fatalf("renewal was not observed in logs: %s", logger.String())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown=%v", err)
	}
}

func TestACMEAccountCacheIsStablePerEmailAndSeparatedOnChange(t *testing.T) {
	root := t.TempDir()
	first := acmeCacheDir(root, "admin@example.org")
	same := acmeCacheDir(root, "admin@example.org")
	changed := acmeCacheDir(root, "other@example.org")
	caseChanged := acmeCacheDir(root, "Admin@example.org")
	without := acmeCacheDir(root, "")
	if first != same || first == changed || first == caseChanged || changed == without || filepath.Dir(first) != filepath.Join(root, "acme") {
		t.Fatalf("cache first=%q same=%q changed=%q case=%q without=%q", first, same, changed, caseChanged, without)
	}
}

func TestACMECertificateMustMatchDomainAndBeCurrentlyValid(t *testing.T) {
	manager := newFakeACMEManager(t)
	cert, err := prefetchACMECertificate(manager, "Router.ACME-VALID.COM.")
	if err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	if _, err := prefetchACMECertificate(manager, "other.example.org"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong-domain certificate error=%v", err)
	}
	leaf, err := validateACMECertificate(cert, "router.acme-valid.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateACMECertificate(cert, "router.acme-valid.com", leaf.NotBefore.Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("future certificate error=%v", err)
	}
	if _, err := validateACMECertificate(cert, "router.acme-valid.com", leaf.NotAfter); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired certificate error=%v", err)
	}
}

func TestACMEIssuanceFailureNeverSignalsReadyAndReleasesChallengePort(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	manager := newFakeACMEManager(t)
	manager.issueErr = fmt.Errorf("injected CA failure")
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.acme-valid.com", AcceptTOS: true}
	s := New(nil, nil, nil, &lifecycleLogger{})
	s.ACMEHTTPAddress = address
	s.ACMEFactory = func(_, _, _ string) (acmeCertificateManager, error) { return manager, nil }
	ready := false
	s.Ready = func() error { ready = true; return nil }
	err = s.Start(context.Background(), cfg, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "injected CA failure") || ready {
		t.Fatalf("error=%v ready=%v", err, ready)
	}
	ln, listenErr := net.Listen("tcp", address)
	if listenErr != nil {
		t.Fatalf("challenge port leaked: %v", listenErr)
	}
	_ = ln.Close()
}

func TestACMEChallengeCollisionFailsBeforeIssuance(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	manager := newFakeACMEManager(t)
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.acme-valid.com", AcceptTOS: true}
	s := New(nil, nil, nil, &lifecycleLogger{})
	s.ACMEHTTPAddress = occupied.Addr().String()
	s.ACMEFactory = func(_, _, _ string) (acmeCertificateManager, error) { return manager, nil }
	err = s.Start(context.Background(), cfg, t.TempDir())
	manager.mu.Lock()
	requests := len(manager.requested)
	manager.mu.Unlock()
	if err == nil || requests != 0 {
		t.Fatalf("collision error=%v issuance requests=%d", err, requests)
	}
}

func TestProductionACMEManagerProtectsCacheAndRejectsOtherHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	manager, err := newProductionACMEManager(dir, "router.acme-valid.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(dir)
		if statErr != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("cache mode=%v err=%v", info.Mode().Perm(), statErr)
		}
	}
	_, err = manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example.org"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not configured") {
		t.Fatalf("foreign host policy error=%v", err)
	}
	blocked := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newProductionACMEManager(blocked, "router.acme-valid.com", ""); err == nil {
		t.Fatal("regular file accepted as ACME cache")
	}
}

func TestACMEFallbackExposesNoPanelContent(t *testing.T) {
	recorder := httptest.NewRecorder()
	acmeFallback(recorder, httptest.NewRequest(http.MethodGet, "http://router.invalid/not-a-challenge", nil))
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("fallback status=%d cache=%q body=%q", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
}
