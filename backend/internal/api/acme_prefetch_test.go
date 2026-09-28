package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/netos-router/netos/internal/tlsutil"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	"testing"
)

type offlineACMETransport struct{}

func (offlineACMETransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected CA request: ECDSA certificate already cached")
}
func TestACMEPrefetchUsesCertificateForModernTLSClient(t *testing.T) {
	dir := t.TempDir()
	domain := "router.example.test"
	certPath, keyPath, _, err := tlsutil.EnsureSelfSigned(t.TempDir(), domain)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(keyPath)
	cert, _ := os.ReadFile(certPath)
	cache := autocert.DirCache(dir)
	if err := cache.Put(context.Background(), domain, append(key, cert...)); err != nil {
		t.Fatal(err)
	}
	m := &autocert.Manager{Cache: cache, Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(domain), Client: &acme.Client{HTTPClient: &http.Client{Transport: offlineACMETransport{}}}}
	prefetched, err := prefetchACMECertificate(m, domain)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: domain, SupportedVersions: []uint16{tls.VersionTLS13}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, SupportedCurves: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	if string(actual.Certificate[0]) != string(prefetched.Certificate[0]) {
		t.Fatal("readiness handshake needs a different certificate")
	}
}
