package api

import (
	"encoding/json"
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestOpenConnectCertificateSecrets(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{{ID: "oc", Type: "openconnect", Config: map[string]any{"auth_mode": "certificate", "client_certificate": "private-container-marker", "certificate_password": "container-password-marker"}}}
	visible, err := redactAdminConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(visible)
	if strings.Contains(string(raw), "private-container-marker") || strings.Contains(string(raw), "container-password-marker") {
		t.Fatal("credential leak")
	}
	if !visible.Channels[0].SecretsSet["client_certificate"] || !visible.Channels[0].SecretsSet["certificate_password"] {
		t.Fatal("secret presence missing")
	}
	diagnostic, err := diagnosticConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(diagnostic)
	if strings.Contains(string(raw), "private-container-marker") || strings.Contains(string(raw), "container-password-marker") {
		t.Fatal("diagnostic leak")
	}
	mergeRedactedSecrets(visible, cfg)
	if visible.Channels[0].Config["client_certificate"] != "private-container-marker" {
		t.Fatal("saved certificate lost")
	}
	delete(visible.Channels[0].Config, "client_certificate")
	delete(visible.Channels[0].Config, "certificate_password")
	mergeRedactedSecrets(visible, cfg)
	if _, ok := visible.Channels[0].Config["client_certificate"]; ok {
		t.Fatal("removed certificate restored")
	}
}
