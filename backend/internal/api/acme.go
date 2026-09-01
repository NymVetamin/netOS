package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type acmeCertificateManager interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	HTTPHandler(http.Handler) http.Handler
	TLSConfig() *tls.Config
}

type acmeManagerFactory func(cacheDir, domain, email string) (acmeCertificateManager, error)

func newProductionACMEManager(cacheDir, domain, email string) (acmeCertificateManager, error) {
	if err := secureACMECacheDir(cacheDir); err != nil {
		return nil, err
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	return &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(cacheDir),
		HostPolicy:  autocert.HostWhitelist(domain),
		Email:       email,
		RenewBefore: 30 * 24 * time.Hour,
	}, nil
}

func secureACMECacheDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create ACME cache: %w", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("inspect ACME cache: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ACME cache %s is not a real directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect ACME cache: %w", err)
	}
	return nil
}

func acmeCacheDir(tlsDir, email string) string {
	identity := strings.TrimSpace(email)
	if identity == "" {
		identity = "no-email"
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(tlsDir, "acme", fmt.Sprintf("%x", digest[:8]))
}

func acmeFallback(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "ACME challenge endpoint", http.StatusNotFound)
}

func prefetchACMECertificate(manager acmeCertificateManager, domain string) (*tls.Certificate, error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	cert, err := manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName:        domain,
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
	})
	if err != nil {
		return nil, fmt.Errorf("ACME certificate issuance: %w", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("ACME returned an empty certificate")
	}
	if _, err := validateACMECertificate(cert, domain, time.Now()); err != nil {
		return nil, err
	}
	return cert, nil
}

func validateACMECertificate(cert *tls.Certificate, domain string, now time.Time) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("ACME returned an empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse ACME certificate: %w", err)
	}
	if err := leaf.VerifyHostname(strings.TrimSuffix(strings.ToLower(domain), ".")); err != nil {
		return nil, fmt.Errorf("ACME certificate does not match requested domain: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("ACME certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("ACME certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return leaf, nil
}

func prefetchACMECertificateContext(ctx context.Context, manager acmeCertificateManager, domain string) (*tls.Certificate, error) {
	type result struct {
		cert *tls.Certificate
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cert, err := prefetchACMECertificate(manager, domain)
		done <- result{cert: cert, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.cert, result.err
	}
}
