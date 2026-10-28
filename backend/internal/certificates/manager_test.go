package certificates

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/tlsutil"
)

type testIssuer struct {
	cert      tls.Certificate
	err       error
	httpReady bool
}

func (i *testIssuer) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !i.httpReady {
		return nil, fmt.Errorf("HTTP-01 has not been enabled before issuance")
	}
	return &i.cert, i.err
}
func (i *testIssuer) TLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }
func (i *testIssuer) HTTPHandler(http.Handler) http.Handler {
	i.httpReady = true
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("challenge")) })
}
func makeIssuer(t *testing.T, name string) *testIssuer {
	t.Helper()
	c, k, _, err := tlsutil.EnsureSelfSigned(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	p, err := tls.LoadX509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{cert: p}
}

func TestFailedAccountCanBeCorrectedWithoutDaemonRestart(t *testing.T) {
	good := makeIssuer(t, "vpn.example.test")
	m := New(t.TempDir(), func(_, _, email string) (ACME, error) {
		if email == "bad@example.com" {
			return &testIssuer{err: fmt.Errorf("invalid contact")}, nil
		}
		return good, nil
	})
	m.HTTPAddress = "127.0.0.1:0"
	defer m.Close()
	if _, err := m.acme(context.Background(), "vpn.example.test", "bad@example.com"); err == nil {
		t.Fatal("bad contact accepted")
	}
	if _, err := m.acme(context.Background(), "vpn.example.test", "fixed@example.test"); err != nil {
		t.Fatal("fixed contact still uses failed issuer:", err)
	}
}

func TestSharedCertificateRenewalAndFailure(t *testing.T) {
	issuer := makeIssuer(t, "router.example.test")
	calls := 0
	m := New(t.TempDir(), func(_, _, _ string) (ACME, error) { calls++; return issuer, nil })
	m.HTTPAddress = "127.0.0.1:0"
	defer m.Close()
	cfg := config.Default()
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.example.test"}
	server := config.VPNServer{ID: "vpn", Type: "ocserv", Config: map[string]any{"public_endpoint": "router.example.test:443", "tls": map[string]any{"mode": "panel"}}}
	dir := t.TempDir()
	panelFile, err := m.Panel(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VPN(context.Background(), cfg, server, dir); err != nil {
		t.Fatal(err)
	}
	panel, _ := os.ReadFile(panelFile)
	vpn, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
	if string(panel) != string(vpn) || calls != 1 {
		t.Fatal("shared domain issued separate credentials")
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.pem")); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "panel.crt"))
	if _, err := tls.X509KeyPair(pub, pub); err == nil {
		t.Fatal("public export contains private key")
	}
	issuer.cert = makeIssuer(t, "router.example.test").cert
	if _, err := m.Panel(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	changed, err := m.VPN(context.Background(), cfg, server, dir)
	if err != nil || !changed {
		t.Fatalf("renewal not published: %v", err)
	}
	renewed, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
	if string(renewed) == string(vpn) {
		t.Fatal("old certificate retained after renewal")
	}
	issuer.err = fmt.Errorf("CA unavailable")
	if _, err := m.VPN(context.Background(), cfg, server, dir); err == nil {
		t.Fatal("renewal error hidden")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
	if string(after) != string(renewed) {
		t.Fatal("failure destroyed working certificate")
	}
	server.Config["public_endpoint"] = "other.example.test:443"
	issuer.err = nil
	if _, err := m.VPN(context.Background(), cfg, server, dir); err == nil {
		t.Fatal("wrong shared domain accepted")
	}
}

func TestChallengeRoutingAndIndependentVPN(t *testing.T) {
	calls := map[string]int{}
	m := New(t.TempDir(), func(_, domain, _ string) (ACME, error) { calls[domain]++; return makeIssuer(t, domain), nil })
	m.HTTPAddress = "127.0.0.1:0"
	defer m.Close()
	cfg := config.Default()
	for _, domain := range []string{"one.example.test", "two.example.test"} {
		server := config.VPNServer{ID: domain, Type: "ocserv", Config: map[string]any{"public_endpoint": domain + ":443", "tls": map[string]any{"mode": "acme", "domain": domain}}}
		if _, err := m.VPN(context.Background(), cfg, server, t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		host, path string
		code       int
	}{
		{"one.example.test:80", "/.well-known/acme-challenge/token", 200},
		{"two.example.test", "/.well-known/acme-challenge/token", 200},
		{"unknown.example.test", "/.well-known/acme-challenge/token", 404},
		{"one.example.test", "/api/config", 404},
	} {
		r := httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil)
		w := httptest.NewRecorder()
		m.challenge(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s %s: %d", tc.host, tc.path, w.Code)
		}
	}
	if calls["one.example.test"] != 1 || calls["two.example.test"] != 1 {
		t.Fatal("unexpected issuance")
	}
	if err := m.SetHTTPFallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(302) })); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, path string
		code       int
	}{
		{"one.example.test", "/.well-known/acme-challenge/token", 200},
		{"unknown.example.test", "/.well-known/acme-challenge/token", 404},
		{"one.example.test", "/", 302},
		{"unknown.example.test", "/", 302},
	} {
		w := httptest.NewRecorder()
		m.challenge(w, httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil))
		if w.Code != tc.code {
			t.Fatalf("fallback %v: %d", tc, w.Code)
		}
	}
	if err := m.SetHTTPFallback(nil); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	m.challenge(w, httptest.NewRequest("GET", "http://one.example.test/", nil))
	if w.Code != 404 {
		t.Fatal("fallback survived removal")
	}
}
