package certificates

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestXrayManagedCertificates(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan", "hysteria"} {
		t.Run(protocol, func(t *testing.T) {
			issuer := makeIssuer(t, "vpn.example.test")
			m := New(t.TempDir(), func(_, _, _ string) (ACME, error) { return issuer, nil })
			m.HTTPAddress = "127.0.0.1:0"
			defer m.Close()
			cfg := config.Default()
			cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "vpn.example.test"}
			server := config.VPNServer{ID: "vpn", Type: "xray", Enabled: true, Config: map[string]any{"protocol": protocol, "public_endpoint": "vpn.example.test:443"}}
			dir := t.TempDir()
			for _, mode := range []string{"acme", "panel", "custom"} {
				spec := map[string]any{"mode": mode, "domain": "vpn.example.test"}
				if mode == "custom" {
					pair, err := ReadPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.pem"), "vpn.example.test")
					if err != nil {
						t.Fatal(err)
					}
					spec["cert_pem"], spec["private_key"] = string(pair.Certificate), string(pair.Key)
				}
				server.Config["tls"] = spec
				if _, err := m.VPN(context.Background(), cfg, server, dir); err != nil {
					t.Fatalf("%s: %v", mode, err)
				}
				if changed, err := m.VPN(context.Background(), cfg, server, dir); err != nil || changed {
					t.Fatalf("repeat %s: %v %v", mode, changed, err)
				}
				before, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
				server.Config["public_endpoint"] = "wrong.example.test:443"
				if _, err := m.VPN(context.Background(), cfg, server, dir); err == nil {
					t.Fatal("wrong host accepted")
				}
				after, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
				if string(before) != string(after) {
					t.Fatal("failure replaced working credentials")
				}
				server.Config["public_endpoint"] = "vpn.example.test:443"
			}
		})
	}
}
