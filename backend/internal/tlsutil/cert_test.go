package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func loadCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("certificate PEM was not decoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEnsureSelfSignedGeneratesUsablePairAndSANs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	certPath, keyPath, fingerprint, err := EnsureSelfSignedForNames(
		dir, "router", "vpn.example.test", "192.0.2.10",
	)
	if err != nil {
		t.Fatal(err)
	}
	if certPath != filepath.Join(dir, "panel.crt") || keyPath != filepath.Join(dir, "panel.key") {
		t.Fatalf("unexpected paths: %q %q", certPath, keyPath)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("generated pair is unusable: %v", err)
	}
	cert := loadCertificate(t, certPath)
	for _, name := range []string{"router", "router.lan", "localhost", "vpn.example.test", "192.0.2.10"} {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("certificate does not cover %q: %v", name, err)
		}
	}
	if !cert.IsCA || !cert.NotAfter.After(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("unexpected certificate lifetime/CA flag: IsCA=%v NotAfter=%v", cert.IsCA, cert.NotAfter)
	}
	if fingerprint != Fingerprint(cert) || len(strings.Split(fingerprint, ":")) != sha256.Size {
		t.Fatalf("unexpected fingerprint %q", fingerprint)
	}
	if info, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v", info.Mode().Perm())
	}
}

func TestEnsureSelfSignedReusesValidCertificateAndTightensKeyMode(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, first, err := EnsureSelfSigned(dir, "router")
	if err != nil {
		t.Fatal(err)
	}
	certBefore, _ := os.ReadFile(certPath)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, second, err := EnsureSelfSigned(dir, "router")
	if err != nil {
		t.Fatal(err)
	}
	certAfter, _ := os.ReadFile(certPath)
	if first != second || string(certBefore) != string(certAfter) {
		t.Fatal("valid certificate was unexpectedly rotated")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("reused key mode = %v", info.Mode().Perm())
	}
}

func TestEnsureSelfSignedRotatesWhenSANIsMissing(t *testing.T) {
	dir := t.TempDir()
	_, _, first, err := EnsureSelfSigned(dir, "router")
	if err != nil {
		t.Fatal(err)
	}
	certPath, _, second, err := EnsureSelfSignedForNames(dir, "router", "vpn.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("certificate without requested SAN was reused")
	}
	if err := loadCertificate(t, certPath).VerifyHostname("vpn.example.test"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSelfSignedRepairsMismatchedOrInvalidKey(t *testing.T) {
	for _, variant := range []string{"mismatched", "invalid"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath, first, err := EnsureSelfSigned(dir, "router")
			if err != nil {
				t.Fatal(err)
			}
			if variant == "mismatched" {
				other := t.TempDir()
				_, otherKey, _, err := EnsureSelfSigned(other, "other")
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := os.ReadFile(otherKey)
				if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(keyPath, []byte("not a key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, second, err := EnsureSelfSigned(dir, "router")
			if err != nil {
				t.Fatal(err)
			}
			if first == second {
				t.Fatal("broken key did not rotate certificate")
			}
			if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
				t.Fatalf("repaired pair is unusable: %v", err)
			}
		})
	}
}

func TestFingerprintMatchesSHA256Formatting(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate bytes")}
	wantBytes := sha256.Sum256(cert.Raw)
	wantHex := strings.ToUpper(hex.EncodeToString(wantBytes[:]))
	parts := make([]string, 0, sha256.Size)
	for i := 0; i < len(wantHex); i += 2 {
		parts = append(parts, wantHex[i:i+2])
	}
	if got, want := Fingerprint(cert), strings.Join(parts, ":"); got != want {
		t.Fatalf("Fingerprint() = %q, want %q", got, want)
	}
}

func TestEnsureSelfSignedReportsUnwritableTarget(t *testing.T) {
	parent := t.TempDir()
	blocked := filepath.Join(parent, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := EnsureSelfSigned(blocked, "router"); err == nil {
		t.Fatal("expected target path error")
	}
}

func TestValidatePairForNamesRejectsDrift(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, fingerprint, err := EnsureSelfSignedForNames(dir, "router", "vpn.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ValidatePairForNames(certPath, keyPath, "router", "vpn.example.test"); err != nil || got != fingerprint {
		t.Fatalf("valid pair rejected: fingerprint=%q err=%v", got, err)
	}
	if _, err := ValidatePairForNames(certPath, keyPath, "missing.example.test"); err == nil {
		t.Fatal("missing SAN passed validation")
	}
	other := t.TempDir()
	_, otherKey, _, err := EnsureSelfSigned(other, "other")
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := os.ReadFile(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, foreignKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePairForNames(certPath, keyPath, "router"); err == nil {
		t.Fatal("mismatched key passed validation")
	}
}

func TestEnsureSelfSignedReplacesSymlinkWithoutChangingTarget(t *testing.T) {
	dir := t.TempDir()
	certPath, _, _, err := EnsureSelfSigned(dir, "router")
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign.crt")
	foreignData := []byte("foreign must survive\n")
	if err := os.WriteFile(foreign, foreignData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, certPath); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, _, _, err := EnsureSelfSigned(dir, "router"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(certPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("managed certificate was not replaced by a regular file: info=%v err=%v", info, err)
	}
	if got, err := os.ReadFile(foreign); err != nil || string(got) != string(foreignData) {
		t.Fatalf("foreign symlink target changed: %q err=%v", got, err)
	}
}
