package api

import (
	"encoding/json"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

const diagnosticSecret = "[REDACTED]"

// Diagnostics are routinely copied into support reports. Render a detached
// configuration with placeholders, before a renderer can encode a credential
// (for example, strongSwan's base64 EAP password). Native/CLI renderers continue
// to receive the real configuration.
func diagnosticConfig(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	mask := func(value *string) {
		if *value != "" {
			*value = diagnosticSecret
		}
	}
	for i := range out.WANs {
		mask(&out.WANs[i].Password)
	}
	for i := range out.WiFi {
		for j := range out.WiFi[i].SSIDs {
			mask(&out.WiFi[i].SSIDs[j].Password)
		}
	}
	mask(&out.DDNS.Token)
	mask(&out.DDNS.Password)
	for i := range out.Channels {
		maskDiagnosticValue(out.Channels[i].Config, false)
	}
	for i := range out.VPNServers {
		maskDiagnosticValue(out.VPNServers[i].Config, false)
		for j := range out.VPNServers[i].Peers {
			for key, value := range out.VPNServers[i].Peers[j].Credentials {
				if diagnosticSecretKey(key) && value != "" {
					out.VPNServers[i].Peers[j].Credentials[key] = diagnosticSecret
				}
			}
		}
	}
	return &out, nil
}

func diagnosticSecretKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
	return strings.Contains(key, "password") || strings.Contains(key, "secret") ||
		strings.Contains(key, "privatekey") || strings.Contains(key, "presharedkey") ||
		strings.Contains(key, "token") || key == "uuid" || key == "id" ||
		key == "shortid" || key == "shortids" || key == "key" ||
		key == "pass" || key == "auth" || strings.HasSuffix(key, "seed") ||
		key == "echserverkeys" || key == "encryption" || key == "decryption" ||
		key == "authorization" || key == "proxyauthorization" || key == "cookie"
}

// Preserve value types: e.g. Reality short_ids and inline TLS keys are arrays,
// and their enclosing protocol config is decoded into typed structures later.
// IDs here belong to credentials inside protocol maps, not netOS object IDs.
func maskDiagnosticValue(value any, secret bool) any {
	switch v := value.(type) {
	case string:
		if secret && v != "" {
			return diagnosticSecret
		}
	case map[string]any:
		for key, item := range v {
			// "none" is a protocol mode, not key material.
			if !secret && (key == "encryption" || key == "decryption") && item == "none" {
				continue
			}
			v[key] = maskDiagnosticValue(item, secret || diagnosticSecretKey(key))
		}
	case []any:
		for i, item := range v {
			v[i] = maskDiagnosticValue(item, secret)
		}
	}
	return value
}
