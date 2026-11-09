package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestVPNValidationAndFreshness(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := func(serial int64, kind string) []byte {
		t.Helper()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"vpn.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		switch kind {
		case "expired":
			leaf.NotAfter = now.Add(-time.Minute)
		case "future":
			leaf.NotBefore = now.Add(time.Minute)
		case "client-only":
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		chain := caDER
		if kind == "broken-chain" {
			chain = []byte("invalid DER")
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain})...)
	}
	valid, renewed := certificate(2, "valid"), certificate(3, "valid")
	for _, mode := range []string{"custom", "panel", "acme"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			issuer := &testIssuer{}
			m := New(root, func(_, _, _ string) (ACME, error) { return issuer, nil })
			m.HTTPAddress = "127.0.0.1:0"
			defer m.Close()
			cfg := config.Default()
			certFile, keyFile := filepath.Join(root, "source.crt"), filepath.Join(root, "source.key")
			cfg.System.Panel.TLS = config.TLS{Mode: "custom", CertFile: certFile, KeyFile: keyFile}
			spec := map[string]any{"mode": mode, "domain": "vpn.example.test"}
			server := config.VPNServer{ID: "vpn", Type: "ocserv", Config: map[string]any{"tls": spec, "public_endpoint": "VPN.EXAMPLE.TEST.:443"}}
			dir := filepath.Join(root, "output")
			set := func(cert []byte) {
				t.Helper()
				spec["cert_pem"], spec["private_key"] = string(cert), string(keyPEM)
				for path, data := range map[string][]byte{certFile: cert, keyFile: keyPEM} {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				issuer.cert, err = tls.X509KeyPair(cert, keyPEM)
				if err != nil {
					t.Fatal(err)
				}
			}
			read := func() []byte {
				t.Helper()
				body, err := os.ReadFile(filepath.Join(dir, "server.pem"))
				if err != nil {
					t.Fatal(err)
				}
				return body
			}
			set(valid)
			if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || !changed {
				t.Fatal(changed, err)
			}
			before := read()
			for _, kind := range []string{"expired", "future", "client-only", "broken-chain"} {
				set(certificate(4, kind))
				if _, err := m.VPN(context.Background(), cfg, server, dir); err == nil {
					t.Fatal("invalid certificate accepted", kind)
				}
				if !bytes.Equal(before, read()) {
					t.Fatal("failure replaced working certificate", kind)
				}
				set(valid)
				if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || changed {
					t.Fatal("retry", changed, err)
				}
			}
			set(renewed)
			if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || !changed || bytes.Equal(before, read()) {
				t.Fatal("renewal not published", changed, err)
			}
		})
	}
}
