package vpnpki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/netos-router/netos/internal/config"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReconcileReusesAndRenewsCRL(t *testing.T) {
	ctx := context.Background()
	s := New(t.TempDir(), &p12Runner{})
	server := fixture()
	cfg := &config.Config{VPNServers: []config.VPNServer{server}}
	sync := func() {
		t.Helper()
		if err := s.Reconcile(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	sync()
	dir := s.Dir(server.ID)
	path := filepath.Join(dir, "revoked.crl")
	statePath := filepath.Join(dir, "state.json")
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	stable := func() {
		t.Helper()
		stateData, crl := read(statePath), read(path)
		stamp := time.Unix(1700000000, 0)
		for _, p := range []string{path, statePath} {
			if err := os.Chtimes(p, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		s = New(s.Root, &p12Runner{})
		sync()
		if !bytes.Equal(stateData, read(statePath)) || !bytes.Equal(crl, read(path)) {
			t.Fatal("repeated reconciliation replaced state or CRL")
		}
		for _, p := range []string{path, statePath} {
			if info, err := os.Stat(p); err != nil || !info.ModTime().Equal(stamp) {
				t.Fatalf("unexpected write to %s", filepath.Base(p))
			}
		}
	}
	stable()
	st, err := s.load(server.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	ca, signer, err := st.signer()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(st.CRLNumber), ThisUpdate: now.Add(-6 * 24 * time.Hour), NextUpdate: now.Add(time.Hour),
	}, ca, signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, damaged := range []bool{false, true} {
		if damaged {
			der[len(der)-1] ^= 1
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
			t.Fatal(err)
		}
		old := st.CRLNumber
		sync()
		st, err = s.load(server.ID, false)
		if err != nil || st.CRLNumber != old+1 || !currentCRL(path, st, now) {
			t.Fatalf("CRL was not renewed: %v", err)
		}
		// Corrupt the signature of an otherwise fresh, correctly numbered list.
		block, _ := pem.Decode(read(path))
		der = block.Bytes
	}
	cfg.VPNServers = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Reconcile(ctx, cfg); err == nil {
		t.Fatal("server deletion ignored the CRL publication error")
	}
	st, err = s.load(server.ID, false)
	if err != nil || !st.Clients["phone"].Revoked {
		t.Fatalf("publication failure lost the durable revocation: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	sync()
	st, err = s.load(server.ID, false)
	if err != nil || !st.Clients["phone"].Revoked || len(st.Revocations) != 1 || !currentCRL(path, st, now) {
		t.Fatalf("server deletion lost revocation: %v", err)
	}
	stable()
}

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
		if err := s.publish(st, server, enabledOcservConfig(server)); err != nil {
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
	stamp := time.Unix(1700000000, 0)
	paths := []string{allowedPath, filepath.Join(s.Dir(server.ID), "ca.crt")}
	for _, path := range paths {
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	number := st.CRLNumber
	check("netos-good\nnetos-good\n")
	checkCRL()
	if st.CRLNumber != number+1 {
		t.Fatal("repeat did not refresh CRL")
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.ModTime().Equal(stamp) {
			t.Fatalf("unchanged %s was replaced: %v", filepath.Base(path), err)
		}
	}
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
	if err = s.publish(st, server, enabledOcservConfig(server)); err == nil {
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
