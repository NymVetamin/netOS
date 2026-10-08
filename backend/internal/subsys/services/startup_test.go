package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestStartupDNSRestoresOnlySavedSelectedResolver(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "unbound", "dnsproxy"} {
		for _, scenario := range []string{"saved", "system resolver", "stale config", "foreign unit", "missing config", "disabled"} {
			t.Run(provider+"/"+scenario, func(t *testing.T) {
				r := &serviceRunner{}
				m := NewManager(r)
				m.Resolv.Root = t.TempDir()
				cfg := config.Default()
				cfg.DNS.Enabled, cfg.DNS.Port, cfg.DNS.Provider = true, 53, provider
				cfg.DHCP.Enabled = false
				path, unit, content, unitContent := dnsmasqConfPath, dnsmasqUnit, m.Dnsmasq.Render(cfg), dnsmasqUnitContent()
				if provider == "unbound" {
					path, unit, content, unitContent = unboundConfPath, unboundUnit, m.Unbound.Render(cfg), unboundUnitContent()
				}
				if provider == "dnsproxy" {
					path, unit, content, unitContent = dnsproxyConfPath, dnsproxyUnit, m.Dnsproxy.Render(cfg), dnsproxyUnitContent()
				}
				resolver := m.Resolv.Render(cfg)
				if scenario == "system resolver" {
					resolver = "nameserver 192.0.2.53\n"
				}
				if scenario == "stale config" {
					content += "# stale\n"
				}
				if scenario == "foreign unit" {
					unitContent = "[Service]\nExecStart=/bin/false\n"
				}
				files := map[string]string{path: content, filepath.Join(systemdUnitDir, unit): unitContent, m.Resolv.path(resolvConfPath): resolver}
				for p, data := range files {
					if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(data), 0644); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Remove(p) })
				}
				if scenario == "missing config" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "disabled" {
					cfg.DNS.Enabled = false
				}
				err := NewDNS(m).RecoverStartup(context.Background(), cfg)
				wantError := scenario == "stale config" || scenario == "foreign unit" || scenario == "missing config"
				if (err != nil) != wantError {
					t.Fatalf("error=%v want error=%v", err, wantError)
				}
				want := ""
				if scenario == "saved" {
					want = "systemctl start " + unit
				}
				if got := strings.Join(r.commands, "\n"); got != want {
					t.Fatalf("commands=%q want=%q", got, want)
				}
				data, err := os.ReadFile(m.Resolv.path(resolvConfPath))
				if err != nil || string(data) != resolver {
					t.Fatalf("recovery changed resolver: %v %s", err, data)
				}
			})
		}
	}
}
