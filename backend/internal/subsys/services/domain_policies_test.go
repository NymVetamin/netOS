package services

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/policy"
)

func dnsDomainPolicyConfig(provider string) *config.Config {
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = provider
	cfg.DNS.Port = 53
	cfg.DNS.QueryLog = true
	cfg.Policies = []config.Policy{{
		ID: "video", Name: "Video", Enabled: true, Priority: 10, Channel: "direct",
		Domains: []string{"Example.COM.", "cdn.example.net"},
	}}
	return cfg
}

func TestDomainPolicyDNSFrontendAllProviders(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "unbound", "dnsproxy"} {
		t.Run(provider, func(t *testing.T) {
			cfg := dnsDomainPolicyConfig(provider)
			front := NewDnsmasq(nil).Render(cfg)
			for _, want := range []string{
				"max-ttl=" + strconv.Itoa(policy.DomainSetTimeout),
				"max-cache-ttl=" + strconv.Itoa(policy.DomainSetTimeout),
				"ipset=/cdn.example.net/example.com/" + policy.IPv4SetName("video"),
			} {
				if !strings.Contains(front, want) {
					t.Errorf("frontend missing %q:\n%s", want, front)
				}
			}
			if provider == "dnsmasq" {
				if strings.Contains(front, "127.0.0.1#5355") || !strings.Contains(front, "server=1.1.1.1") {
					t.Fatalf("native dnsmasq upstreams wrong:\n%s", front)
				}
				return
			}
			if !strings.Contains(front, "server=127.0.0.1#5355") || strings.Contains(front, "server=1.1.1.1") {
				t.Fatalf("frontend backend routing wrong:\n%s", front)
			}
			if provider == "unbound" {
				backend := NewUnbound(nil).Render(cfg)
				if !strings.Contains(backend, "port: 5355") || strings.Contains(backend, "interface: 192.168.50.1") || strings.Contains(backend, "log-queries: yes") {
					t.Fatalf("unbound backend exposure/logging wrong:\n%s", backend)
				}
			} else {
				backend := NewDnsproxy(nil).Render(cfg)
				if !strings.Contains(backend, "  - 5355") || strings.Contains(backend, `  - "192.168.50.1"`) || strings.Contains(backend, "verbose: true") {
					t.Fatalf("dnsproxy backend exposure/logging wrong:\n%s", backend)
				}
			}
		})
	}
}

func TestXrayInboundDomainsDoNotEnableDNSFrontend(t *testing.T) {
	cfg := dnsDomainPolicyConfig("unbound")
	cfg.VPNServers = []config.VPNServer{{ID: "reality", Type: "xray"}}
	cfg.Policies[0].VPNServer = "reality"
	if hasKernelDomainPolicies(cfg) {
		t.Fatal("Xray-native domains enabled kernel DNS frontend")
	}
	if output := NewDnsmasq(nil).Render(cfg); strings.Contains(output, "ipset=/") || strings.Contains(output, "127.0.0.1#5355") {
		t.Fatalf("Xray-native domain leaked into dnsmasq:\n%s", output)
	}
}

func TestDomainPolicyStartsBackendBeforeDNSFrontend(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	cfg := dnsDomainPolicyConfig("unbound")
	if err := NewDNS(m).Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	backend, front := -1, -1
	for i, command := range r.commands {
		if strings.Contains(command, "systemctl restart "+unboundUnit) {
			backend = i
		}
		if strings.Contains(command, "systemctl restart "+dnsmasqUnit) {
			front = i
		}
	}
	if backend < 0 || front < 0 || backend > front {
		t.Fatalf("backend/front order backend=%d front=%d commands=%v", backend, front, r.commands)
	}
	if !hasCommand(r.commands, "unbound-checkconf") || !hasCommand(r.commands, "dnsmasq --test") {
		t.Fatalf("both configs were not preflighted: %v", r.commands)
	}
}

func TestDomainPolicyFrontendFailureRestoresFirstApplyState(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	r.failContains = "systemctl restart " + dnsmasqUnit
	err := NewDNS(m).Apply(context.Background(), dnsDomainPolicyConfig("unbound"))
	if err == nil {
		t.Fatal("injected frontend failure accepted")
	}
	for _, path := range []string{
		dnsmasqConfPath, unboundConfPath,
		filepath.Join(systemdUnitDir, dnsmasqUnit), filepath.Join(systemdUnitDir, unboundUnit),
	} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("partial DNS transition file survived: %s (%v)", path, statErr)
		}
	}
	if r.active[dnsmasqUnit] || r.active[unboundUnit] {
		t.Fatalf("partial DNS services survived: %+v", r.active)
	}
}

func TestDomainPolicyFrontendFailureRestoresExistingFilesAndServices(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	old := map[string]string{
		dnsmasqConfPath: "old dnsmasq\n", unboundConfPath: "old unbound\n",
		filepath.Join(systemdUnitDir, dnsmasqUnit): "old dnsmasq unit\n",
		filepath.Join(systemdUnitDir, unboundUnit): "old unbound unit\n",
	}
	for path, content := range old {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.active[dnsmasqUnit], r.active[unboundUnit] = true, true
	r.failContains = "systemctl restart " + dnsmasqUnit
	err := NewDNS(m).Apply(context.Background(), dnsDomainPolicyConfig("unbound"))
	if err == nil {
		t.Fatal("injected frontend failure accepted")
	}
	for path, want := range old {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != want {
			t.Fatalf("rollback %s=%q err=%v want=%q", path, data, readErr, want)
		}
	}
	if !r.active[dnsmasqUnit] || !r.active[unboundUnit] {
		t.Fatalf("previous active services not restored: %+v", r.active)
	}
}
