package vpnpki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Unit tests exercise the PKI state machine. Real PKCS#12 encryption and
// OpenConnect imports are separately verified on Linux with OpenSSL/ocserv.
type p12Runner struct{ fail bool }

func (r *p12Runner) Run(context.Context, string, ...string) (string, error) { return "", nil }
func (r *p12Runner) RunInput(_ context.Context, input, name string, args ...string) (string, error) {
	if r.fail {
		return "", fmt.Errorf("openssl unavailable")
	}
	for i, arg := range args {
		if arg == "-out" {
			return "", os.WriteFile(args[i+1], []byte("test-container:"+input), 0600)
		}
	}
	return "", fmt.Errorf("missing output")
}
func fixture() config.VPNServer {
	return config.VPNServer{ID: "server1", Type: "ocserv", Enabled: true, Config: map[string]any{"auth_mode": "certificate"}, Peers: []config.VPNPeer{{ID: "phone", Enabled: true}}}
}
func TestIdentityReexportDisableRevokeReissueAndHistory(t *testing.T) {
	ctx := context.Background()
	runner := &p12Runner{}
	s := New(t.TempDir(), runner)
	server := fixture()
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	first, err := s.Get(server.ID, "phone")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(first.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "netos-phone" || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("wrong certificate identity or usage")
	}
	s = New(s.Root, runner)
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	same, _ := s.Get(server.ID, "phone")
	if string(same.P12) != string(first.P12) || same.Password != first.Password || same.Serial != first.Serial {
		t.Fatal("profile rotated on reload")
	}
	server.Peers[0].Enabled = false
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	allowed, _ := os.ReadFile(filepath.Join(s.Dir(server.ID), "allowed"))
	if strings.Contains(string(allowed), "netos-phone") {
		t.Fatal("disabled client allowed")
	}
	server.Peers[0].Enabled = true
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	allowed, _ = os.ReadFile(filepath.Join(s.Dir(server.ID), "allowed"))
	if !strings.Contains(string(allowed), "netos-phone") {
		t.Fatal("reenabled client denied")
	}
	if err := s.Revoke(server, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	revoked, _ := s.Get(server.ID, "phone")
	if !revoked.Revoked || revoked.Serial != first.Serial {
		t.Fatal("rollback resurrected revoked identity")
	}
	if err := s.Reissue(ctx, server, server.Peers[0]); err != nil {
		t.Fatal(err)
	}
	renewed, _ := s.Get(server.ID, "phone")
	if renewed.Revoked || renewed.Serial == first.Serial || renewed.Password == first.Password {
		t.Fatal("reissue did not replace profile")
	}
	data, _ := os.ReadFile(filepath.Join(s.Dir(server.ID), "revoked.crl"))
	block, _ = pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.String() != first.Serial {
		t.Fatal("old serial missing from CRL")
	}
	cfg := config.Default()
	cfg.VPNServers = nil
	if err := s.Reconcile(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	removed, _ := s.Get(server.ID, "phone")
	if !removed.Revoked {
		t.Fatal("server deletion undone by history")
	}
}
func TestFailedReissuePreservesIdentityAndSeparateServersHaveSeparateCA(t *testing.T) {
	ctx := context.Background()
	runner := &p12Runner{}
	s := New(t.TempDir(), runner)
	server := fixture()
	if err := s.Sync(ctx, server); err != nil {
		t.Fatal(err)
	}
	first, _ := s.Get(server.ID, "phone")
	runner.fail = true
	if err := s.Reissue(ctx, server, server.Peers[0]); err == nil {
		t.Fatal("failed export accepted")
	}
	after, _ := s.Get(server.ID, "phone")
	if after.Serial != first.Serial || after.Revoked {
		t.Fatal("failed reissue damaged working profile")
	}
	runner.fail = false
	other := fixture()
	other.ID = "server2"
	if err := s.Sync(ctx, other); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(s.Dir(server.ID), "ca.crt"))
	b, _ := os.ReadFile(filepath.Join(s.Dir(other.ID), "ca.crt"))
	if string(a) == string(b) {
		t.Fatal("servers share CA")
	}
}
