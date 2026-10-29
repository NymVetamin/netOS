package vpnservers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/certificates"
	"github.com/netos-router/netos/internal/tlsutil"
)

func TestXrayTLSApplyRepeatAndFailure(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan", "hysteria"} {
		t.Run(protocol, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			s.UnitDir = t.TempDir()
			s.Certificates = certificates.New(t.TempDir(), nil)
			defer s.Certificates.Close()
			var restarts int
			fail := false
			s.Runner = vpnRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
				if name == "/usr/local/bin/xray" && fail {
					return "", fmt.Errorf("candidate failed")
				}
				if name == "systemctl" && len(args) > 0 {
					if args[0] == "restart" {
						restarts++
					}
					if args[0] == "is-active" {
						return "active", nil
					}
					if args[0] == "is-enabled" {
						return "enabled", nil
					}
				}
				return "", nil
			})
			cfg, server := xrayServerConfig()
			server.Config["protocol"], server.Config["public_endpoint"] = protocol, "vpn.example.test:443"
			if _, err := s.applyXray(context.Background(), cfg, server, false); err != nil {
				t.Fatal(err)
			}
			certDir := filepath.Join(s.StateDir, "xray-srv2-tls")
			original, _ := os.ReadFile(filepath.Join(certDir, "panel.crt"))
			if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil || restarts != 1 {
				t.Fatalf("repeat: %v, restarts %d", err, restarts)
			}
			c, k, _, err := tlsutil.EnsureSelfSignedForNames(t.TempDir(), "vpn.example.test")
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := os.ReadFile(c)
			key, _ := os.ReadFile(k)
			server.Config["tls"] = map[string]any{"mode": "custom", "cert_pem": string(cert), "private_key": string(key)}
			fail = true
			if _, err := s.applyXray(context.Background(), cfg, server, true); err == nil {
				t.Fatal("candidate failure ignored")
			}
			after, _ := os.ReadFile(filepath.Join(certDir, "panel.crt"))
			if string(after) != string(original) {
				t.Fatal("failed candidate changed certificate")
			}
			fail = false
			if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil {
				t.Fatal(err)
			}
			conf, _ := os.ReadFile(filepath.Join(s.StateDir, "xray-srv2.json"))
			if !strings.Contains(string(conf), "server.pem") || strings.Contains(string(conf), "panel.key") {
				t.Fatal("managed certificate not used")
			}
			before := restarts
			if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil || restarts != before {
				t.Fatalf("managed repeat restarted: %v", err)
			}
			delete(server.Config, "tls")
			if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil {
				t.Fatal(err)
			}
			if _, err := tlsutil.ValidatePairForNames(filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"), cfg.System.Hostname, "vpn.example.test"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
