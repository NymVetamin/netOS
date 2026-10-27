package vpnpki

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestPublishAllowlistAndFailedWriteRecovery(t *testing.T) {
	s := New(t.TempDir(), &p12Runner{})
	server := fixture()
	st, err := s.load(server.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	st.Clients = map[string]Client{
		"good":     {Serial: "1", Expires: future},
		"disabled": {Serial: "2", Expires: future},
		"expired":  {Serial: "3", Expires: past},
		"revoked":  {Serial: "4", Expires: future, Revoked: true},
	}
	st.Revocations = []revocation{{Serial: "4", At: past}}
	server.Peers = []config.VPNPeer{{ID: "revoked", Enabled: true}, {ID: "expired", Enabled: true}, {ID: "disabled"}, {ID: "missing", Enabled: true}, {ID: "good", Enabled: true}, {ID: "good", Enabled: true}}
	allowedPath := filepath.Join(s.Dir(server.ID), "allowed")
	check := func(want string) {
		t.Helper()
		if err := s.publish(st, server); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(allowedPath)
		if err != nil || string(data) != want {
			t.Fatalf("allowlist %q err %v want %q", data, err, want)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(allowedPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("wrong allowlist permissions")
			}
		}
	}
	checkCRL := func() {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(s.Dir(server.ID), "revoked.crl"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("missing CRL PEM")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ca, _, err := st.signer()
		if err != nil {
			t.Fatal(err)
		}
		if err = crl.CheckSignatureFrom(ca); err != nil {
			t.Fatal(err)
		}
		if crl.Number.Int64() != st.CRLNumber || len(crl.RevokedCertificateEntries) != len(st.Revocations) {
			t.Fatal("CRL differs from durable state")
		}
		for i, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.String() != st.Revocations[i].Serial {
				t.Fatal("revoked serial missing")
			}
		}
	}
	check("netos-good\nnetos-good\n")
	checkCRL()
	server.Enabled = false
	check("\n")
	server.Enabled = true
	check("netos-good\nnetos-good\n")
	server.Config["auth_mode"] = "password"
	check("\n")
	server.Config["auth_mode"] = "certificate_password"
	check("netos-good\nnetos-good\n")
	// An allowlist write failure must not undo the already persisted revocation.
	revoke(st, "good")
	previousNumber := st.CRLNumber
	if err = os.Remove(allowedPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(allowedPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = s.publish(st, server); err == nil {
		t.Fatal("write obstruction was ignored")
	}
	persisted, err := s.load(server.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Clients["good"].Revoked || len(persisted.Revocations) != 2 || persisted.CRLNumber != previousNumber+1 {
		t.Fatal("failed publication lost durable revocation")
	}
	if err = os.Remove(allowedPath); err != nil {
		t.Fatal(err)
	}
	st = persisted
	check("\n")
	checkCRL()
	check("\n")
	checkCRL()
}
