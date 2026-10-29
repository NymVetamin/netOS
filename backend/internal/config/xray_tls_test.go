package config

import "testing"

func TestXrayTLSValidationAndACME(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan", "hysteria"} {
		cfg := Default()
		cfg.VPNServers = []VPNServer{{ID: "x", Type: "xray", Enabled: true, Port: 443, Config: map[string]any{"protocol": protocol, "public_endpoint": "vpn.example.com:443"}}}
		s := &cfg.VPNServers[0]
		for _, mode := range []string{"selfsigned", "panel", "acme", "custom", "invalid"} {
			s.Config["tls"] = map[string]any{"mode": mode}
			x, err := s.XrayConfig()
			if err != nil {
				t.Fatal(err)
			}
			r := &ValidationResult{}
			cfg.validateVPNServerTLS(r, "server", *s, x.TLS, x.PublicEndpoint)
			wantError := mode == "acme" || mode == "custom" || mode == "invalid"
			if r.HasErrors() != wantError {
				t.Fatalf("%s/%s: %+v", protocol, mode, r)
			}
			if cfg.UsesACME() != (mode == "acme") {
				t.Fatalf("ACME missing for %s/%s", protocol, mode)
			}
		}
		s.Config["tls"] = map[string]any{"mode": "acme"}
		s.Enabled = false
		if cfg.UsesACME() {
			t.Fatal("disabled server opens ACME")
		}
		s.Enabled = true
		s.Config["protocol"] = "reality"
		if cfg.UsesACME() {
			t.Fatal("Reality opens unused ACME")
		}
	}
}
