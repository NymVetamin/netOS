//go:build linux

package system

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeHTTPProbeResponses(t *testing.T) {
	var followed atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/followed")
			w.WriteHeader(302)
		case "/bad-redirect":
			w.Header().Set("Location", "://%")
			w.WriteHeader(302)
		case "/followed":
			followed.Add(1)
		case "/bad":
			w.WriteHeader(503)
		case "/truncated":
			w.Header().Set("Content-Length", "20")
			fmt.Fprint(w, "short")
		case "/slow":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			fmt.Fprint(w, "healthy")
		}
	}))
	defer s.Close()
	for _, tc := range []struct {
		path    string
		success bool
	}{{"/", true}, {"/redirect", true}, {"/bad-redirect", true}, {"/bad", false}, {"/truncated", false}, {"/slow", false}} {
		t.Run(tc.path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			err := nativeHTTPProbe(ctx, "", s.URL+tc.path, nil)
			if (err == nil) != tc.success {
				t.Fatalf("success=%v err=%v", tc.success, err)
			}
		})
	}
	if followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if nativeHTTPProbe(ctx, "", s.URL, nil) == nil {
		t.Fatal("cancelled probe succeeded")
	}
	if nativeHTTPProbe(context.Background(), "netos-no-such", s.URL, nil) == nil {
		t.Fatal("invalid interface escaped through default route")
	}
}

func TestNativeHTTPProbeTLSAndFreshConnections(t *testing.T) {
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	for i := 0; i < 3; i++ {
		if err := nativeHTTPProbe(context.Background(), "", s.URL, roots); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 3 {
		t.Fatalf("connections=%d", connections.Load())
	}
	if nativeHTTPProbe(context.Background(), "", s.URL, x509.NewCertPool()) == nil {
		t.Fatal("untrusted certificate accepted")
	}
	// The fixture cert includes 127.0.0.1 but not localhost.
	if nativeHTTPProbe(context.Background(), "", strings.Replace(s.URL, "127.0.0.1", "localhost", 1), roots) == nil {
		t.Fatal("wrong hostname accepted")
	}
}

func TestProbeTrustReload(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "ca-certificates.crt")
	c := &probeTrust{}
	p, err := c.roots(dir)
	if err != nil {
		t.Fatal(err)
	}
	if nativeHTTPProbe(context.Background(), "", s.URL, p) == nil {
		t.Fatal("empty trust accepted")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	if err = os.WriteFile(filepath.Join(dir, "untrusted-server.pem"), data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err = c.roots(dir)
	if err != nil {
		t.Fatal(err)
	}
	if nativeHTTPProbe(context.Background(), "", s.URL, p) == nil {
		t.Fatal("unindexed server certificate became a trust anchor")
	}
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err = c.roots(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = nativeHTTPProbe(context.Background(), "", s.URL, p); err != nil {
		t.Fatal(err)
	}
	again, err := c.roots(dir)
	if err != nil || again != p {
		t.Fatal("unchanged trust reparsed", err)
	}
	if err = os.WriteFile(file, []byte("removed certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err = c.roots(dir)
	if err != nil {
		t.Fatal(err)
	}
	if nativeHTTPProbe(context.Background(), "", s.URL, p) == nil {
		t.Fatal("replaced trust still accepted")
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err = c.roots(dir); err != nil {
		t.Fatal(err)
	}
}

func TestProbeCAFileNames(t *testing.T) {
	for _, name := range []string{"ca-certificates.crt", "0123abcd.0", "abcdef01.12"} {
		if !probeCAFile(name) {
			t.Fatal("CA excluded", name)
		}
	}
	for _, name := range []string{"root.pem", "abcdef01.r0", "abcdef01.", "xyzdef01.0", "1234567.0"} {
		if probeCAFile(name) {
			t.Fatal("non CA included", name)
		}
	}
}

func TestNativeProbeEligibility(t *testing.T) {
	keys := []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME"}
	for _, key := range keys {
		t.Setenv(key, "")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if !nativeHTTPProbeAllowed("https://example.test/") {
		t.Fatal("ordinary URL excluded")
	}
	for _, key := range keys {
		t.Setenv(key, "custom")
		if nativeHTTPProbeAllowed("https://example.test/") {
			t.Fatal(key, "ignored")
		}
		t.Setenv(key, "")
	}
	for _, target := range []string{"ftp://example.test/", "https://user:pass@example.test/", "://"} {
		if nativeHTTPProbeAllowed(target) {
			t.Fatal("custom URL", target)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".curlrc"), []byte("--insecure"), 0600); err != nil {
		t.Fatal(err)
	}
	if nativeHTTPProbeAllowed("https://example.test/") {
		t.Fatal("curlrc ignored")
	}
}

func TestNativeProbeWithoutHomeEnvironment(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME", "HOME"} {
		t.Setenv(key, "")
	}
	account, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	for _, name := range []string{filepath.Join(account.HomeDir, ".curlrc"), filepath.Join(account.HomeDir, ".config", "curlrc")} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Skip("account has curl customization or inaccessible home")
		}
	}
	if !nativeHTTPProbeAllowed("https://example.test/") {
		t.Fatal("system service without HOME fell back to curl")
	}
}

func TestExecHTTPProbeTimeoutAndIPv6(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	t.Setenv("HOME", t.TempDir())
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip(err)
	}
	s.Listener.Close()
	s.Listener = l
	s.Start()
	defer s.Close()
	e := NewExec()
	e.Timeout = 100 * time.Millisecond
	if err := ProbeHTTP(context.Background(), e, "", s.URL, time.Second); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if ProbeHTTP(context.Background(), e, "", s.URL+"/slow", time.Second) == nil {
		t.Fatal("timeout ignored")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("runner timeout ignored")
	}
}
