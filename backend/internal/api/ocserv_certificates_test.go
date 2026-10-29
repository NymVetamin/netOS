package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/vpnpki"
)

type ocP12TestRunner struct{}

func (ocP12TestRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }
func (ocP12TestRunner) RunInput(_ context.Context, _, _ string, args ...string) (string, error) {
	for i, arg := range args {
		if arg == "-out" {
			return "", os.WriteFile(args[i+1], []byte("encrypted-test-container"), 0600)
		}
	}
	return "", nil
}

func TestOCProfileExplicitAdminExportAndRedaction(t *testing.T) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "ocserv", Installed: true}}
	cfg.VPNServers = []config.VPNServer{{ID: "oc", Index: 1, Type: "ocserv", Name: "OC", Enabled: true, Port: 14443, Subnet: "10.99.0.1/24", DefaultChannel: "direct", Config: map[string]any{"auth_mode": "certificate"}, Peers: []config.VPNPeer{{ID: "phone", Address: "10.99.0.2", Enabled: true}, {ID: "laptop", Address: "10.99.0.5", Enabled: true}}}}
	pki := vpnpki.New(t.TempDir(), ocP12TestRunner{})
	storedServer := cfg.VPNServers[0]
	storedServer.Peers = append(append([]config.VPNPeer{}, storedServer.Peers...), config.VPNPeer{ID: "removed", Enabled: true, Address: "10.99.0.3"})
	if err := pki.Sync(context.Background(), storedServer); err != nil {
		t.Fatal(err)
	}
	cfg.VPNServers[0].Peers = append(cfg.VPNServers[0].Peers, config.VPNPeer{ID: "pending", Address: "10.99.0.4"})
	engine := apply.NewEngine(&lifecycleLogger{}, false)
	if _, err := engine.Apply(context.Background(), cfg, 1, false); err != nil {
		t.Fatal(err)
	}
	s := &Server{Engine: engine, PKI: pki}
	call := func(role, action string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/certificate", nil)
		r.SetPathValue("id", "oc")
		r.SetPathValue("peer", "phone")
		r.SetPathValue("action", action)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, role))
		w := httptest.NewRecorder()
		s.handleOCClientCertificate(w, r)
		return w
	}
	client, _ := pki.Get("oc", "phone")
	batch := func(role string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/certificates", nil)
		r.SetPathValue("id", "oc")
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, role))
		w := httptest.NewRecorder()
		s.handleOCClientCertificates(w, r)
		return w
	}
	if batch("viewer").Code != 403 {
		t.Fatal("viewer read certificate batch")
	}
	storeMissing := false
	assertBatch := func() {
		t.Helper()
		w := batch("admin")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("batch unavailable", w.Code, w.Body.String())
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &values); err != nil {
			t.Fatal(err)
		}
		if len(values) != 3 || string(values["pending"]) != `{"pending":true}` || string(values["phone"]) != strings.TrimSpace(call("admin", "").Body.String()) {
			t.Fatal("batch differs from individual status", w.Body.String())
		}

		for _, id := range []string{"phone", "laptop"} {
			var value struct {
				Username string `json:"username"`
			}
			if storeMissing {
				if string(values[id]) != `{"pending":true}` {
					t.Fatalf("missing store returned issued identity for %s", id)
				}
				continue
			}
			if err := json.Unmarshal(values[id], &value); err != nil || value.Username != "netos-"+id {
				t.Fatalf("wrong batch identity for %s", id)
			}
		}
	}
	assertBatch()
	applied := engine.Current().VPNServers[0].Config
	applied["auth_mode"] = "password"
	if w := batch("admin"); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "{}" {
		t.Fatal("stale certificate mode")
	}
	applied["auth_mode"] = "certificate"
	assertBatch()
	for _, action := range []string{"", "password", "download"} {
		if w := call("viewer", action); w.Code != 403 {
			t.Fatalf("viewer read %s", action)
		}
	}
	w := call("admin", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), client.Password) || strings.Contains(w.Body.String(), "encrypted-test-container") || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("metadata leaks secrets")
	}
	w = call("admin", "password")
	var password struct{ Password string }
	json.Unmarshal(w.Body.Bytes(), &password)
	if w.Code != 200 || password.Password != client.Password || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("explicit password failed")
	}
	w = call("admin", "download")
	if w.Code != 200 || w.Body.String() != string(client.P12) || w.Header().Get("Content-Type") != "application/x-pkcs12" {
		t.Fatal("explicit P12 failed")
	}
	if err := pki.Revoke(cfg.VPNServers[0], "phone"); err != nil {
		t.Fatal(err)
	}
	assertBatch()
	for _, action := range []string{"password", "download"} {
		if call("admin", action).Code != 409 {
			t.Fatal("revoked profile exported")
		}
	}
	stateFile := filepath.Join(pki.Dir("oc"), "state.json")
	stateBeforeCorruption, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := call("admin", ""); w.Code != 500 || strings.Contains(w.Body.String(), `"pending":true`) {
		t.Fatal("damaged PKI was presented as a pending draft")
	}
	if w := batch("admin"); w.Code != 500 || strings.Contains(w.Body.String(), `"pending":true`) {
		t.Fatal("damaged PKI hidden by batch status")
	}
	if err := os.Remove(filepath.Join(pki.Dir("oc"), "state.json")); err != nil {
		t.Fatal(err)
	}
	storeMissing = true
	assertBatch()
	if err := os.WriteFile(stateFile, stateBeforeCorruption, 0600); err != nil {
		t.Fatal(err)
	}
	storeMissing = false
	assertBatch()
}

func TestOCUploadedKeyIsRetainedButNeverReturned(t *testing.T) {
	for _, serverType := range []string{"ocserv", "xray"} {
		cfg := config.Default()
		cfg.VPNServers = []config.VPNServer{{ID: "oc", Type: serverType, Config: map[string]any{"tls": map[string]any{"mode": "custom", "private_key": "private-key-sensitive", "cert_pem": "public-certificate"}}}}
		visible, err := redactAdminConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(visible)
		if strings.Contains(string(data), "private-key-sensitive") || !visible.VPNServers[0].SecretsSet["tls.private_key"] {
			t.Fatal("key exposure/presence")
		}
		mergeRedactedSecrets(visible, cfg)
		if visible.VPNServers[0].Config["tls"].(map[string]any)["private_key"] != "private-key-sensitive" {
			t.Fatal("saving redacted key erased it")
		}
	}
}
