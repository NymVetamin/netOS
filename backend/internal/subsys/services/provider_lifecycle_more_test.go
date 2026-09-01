package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type providerRunner struct {
	active       map[string]bool
	commands     []string
	failName     string
	failContains string
}

func newProviderRunner() *providerRunner { return &providerRunner{active: map[string]bool{}} }

func (r *providerRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if name == r.failName {
		return "", fmt.Errorf("injected %s failure", name)
	}
	if r.failContains != "" && strings.Contains(command, r.failContains) {
		failure := r.failContains
		r.failContains = ""
		return "", fmt.Errorf("injected %s failure", failure)
	}
	if name == "unbound-anchor" && len(args) >= 2 && args[0] == "-a" {
		if err := os.MkdirAll(filepath.Dir(args[1]), 0o755); err != nil {
			return "", err
		}
		return "", os.WriteFile(args[1], []byte("trust-anchor"), 0o600)
	}
	if name != "systemctl" || len(args) == 0 {
		return "", nil
	}
	unit := ""
	if len(args) > 1 {
		unit = args[len(args)-1]
	}
	switch args[0] {
	case "is-active":
		if r.active[unit] {
			return "active\n", nil
		}
		return "inactive\n", fmt.Errorf("inactive")
	case "restart", "start":
		r.active[unit] = true
	case "stop":
		r.active[unit] = false
	case "is-enabled":
		return "disabled\n", fmt.Errorf("disabled")
	}
	return "", nil
}

func (r *providerRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func useProviderPaths(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	oldUnitDir := systemdUnitDir
	oldDnsmasqConf, oldDnsmasqLease := dnsmasqConfPath, dnsmasqLeasePath
	oldISCConf, oldISCLease := iscConfPath, iscLeasePath
	oldKeaConf, oldKeaLease := keaConfPath, keaLeasePath
	oldUnboundConf, oldAnchor := unboundConfPath, unboundAnchorPath
	oldProxyConf, oldProxyHosts, oldProxyBinary := dnsproxyConfPath, dnsproxyHostsPath, dnsproxyBinary
	oldBlockCache, oldDnsmasqBlock, oldUnboundBlock, oldProxyBlock := blocklistCacheDir, dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath
	systemdUnitDir = filepath.Join(root, "systemd")
	dnsmasqConfPath, dnsmasqLeasePath = filepath.Join(root, "dnsmasq.conf"), filepath.Join(root, "dnsmasq.leases")
	iscConfPath, iscLeasePath = filepath.Join(root, "dhcpd.conf"), filepath.Join(root, "dhcpd.leases")
	keaConfPath, keaLeasePath = filepath.Join(root, "kea.json"), filepath.Join(root, "kea-leases.csv")
	unboundConfPath, unboundAnchorPath = filepath.Join(root, "unbound.conf"), filepath.Join(root, "root.key")
	dnsproxyConfPath, dnsproxyHostsPath, dnsproxyBinary = filepath.Join(root, "dnsproxy.yaml"), filepath.Join(root, "hosts"), filepath.Join(root, "dnsproxy")
	blocklistCacheDir = filepath.Join(root, "blocklists")
	dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath = filepath.Join(root, "dnsmasq-blocklist.conf"), filepath.Join(root, "unbound-blocklist.conf"), filepath.Join(root, "dnsproxy-blocklist.hosts")
	if err := os.WriteFile(dnsproxyBinary, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		systemdUnitDir = oldUnitDir
		dnsmasqConfPath, dnsmasqLeasePath = oldDnsmasqConf, oldDnsmasqLease
		iscConfPath, iscLeasePath = oldISCConf, oldISCLease
		keaConfPath, keaLeasePath = oldKeaConf, oldKeaLease
		unboundConfPath, unboundAnchorPath = oldUnboundConf, oldAnchor
		dnsproxyConfPath, dnsproxyHostsPath, dnsproxyBinary = oldProxyConf, oldProxyHosts, oldProxyBinary
		blocklistCacheDir, dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath = oldBlockCache, oldDnsmasqBlock, oldUnboundBlock, oldProxyBlock
	})
}

func hasCommand(commands []string, fragment string) bool {
	for _, command := range commands {
		if strings.Contains(command, fragment) {
			return true
		}
	}
	return false
}

func TestDnsproxyHostsOnlyChangeRestartsAndCleanRepeatDoesNot(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	d := NewDnsproxy(r)
	cfg := providerTestConfig()
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsproxy"
	cfg.DNS.StaticRecords = []config.DNSRecord{{Type: "A", Name: "printer.lan", Value: "192.168.50.10"}}
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	cfg.DNS.StaticRecords[0].Value = "192.168.50.11"
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !hasCommand(r.commands, "systemctl restart "+dnsproxyUnit) {
		t.Fatalf("hosts-only change did not restart dnsproxy: %v", r.commands)
	}
	r.commands = nil
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if hasCommand(r.commands, "systemctl restart "+dnsproxyUnit) || hasCommand(r.commands, "daemon-reload") {
		t.Fatalf("clean dnsproxy Apply mutated service: %v", r.commands)
	}
}

func TestDnsproxyHealthChecksEveryManagedArtifactAndDisabledCleanup(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	d := NewDnsproxy(r)
	cfg := providerTestConfig()
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsproxy"
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.active[dnsproxyUnit] = false
	if err := d.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "не запущен") {
		t.Fatalf("inactive selected dnsproxy passed Health: %v", err)
	}
	r.active[dnsproxyUnit] = true

	if err := os.Remove(dnsproxyBinary); err != nil {
		t.Fatal(err)
	}
	if err := d.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "binary") {
		t.Fatalf("missing binary passed Health: %v", err)
	}
	if err := os.WriteFile(dnsproxyBinary, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dnsproxyConfPath, dnsproxyHostsPath, filepath.Join(systemdUnitDir, dnsproxyUnit)} {
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(original, []byte("drift")...), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := d.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("drift in %s passed Health: %v", path, err)
		}
		if err := os.WriteFile(path, original, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	disabled := *cfg
	disabled.DNS.Provider = "unbound"
	if err := d.Health(context.Background(), &disabled); err == nil || !strings.Contains(err.Error(), "запущен") {
		t.Fatalf("active unselected dnsproxy passed Health: %v", err)
	}
	r.active[dnsproxyUnit] = false
	if err := d.Health(context.Background(), &disabled); err == nil || !strings.Contains(err.Error(), dnsproxyConfPath) {
		t.Fatalf("stale disabled config passed Health: %v", err)
	}
	if err := os.Remove(dnsproxyConfPath); err != nil {
		t.Fatal(err)
	}
	if err := d.Health(context.Background(), &disabled); err == nil || !strings.Contains(err.Error(), dnsproxyHostsPath) {
		t.Fatalf("stale disabled hosts passed Health: %v", err)
	}
	if err := os.Remove(dnsproxyHostsPath); err != nil {
		t.Fatal(err)
	}
	if err := d.Health(context.Background(), &disabled); err != nil {
		t.Fatalf("clean disabled dnsproxy: %v", err)
	}
}

func TestProviderHealthDetectsConfigUnitAndUnusedDrift(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	cfg := providerTestConfig()
	providers := []struct {
		name           string
		selectProvider func()
		apply          func(context.Context, *config.Config) error
		health         func(context.Context, *config.Config) error
		conf           func() string
		unit           string
	}{
		{"dnsmasq", func() { cfg.DHCP.Provider = "dnsmasq" }, NewDnsmasq(r).Apply, NewDnsmasq(r).Health, func() string { return dnsmasqConfPath }, dnsmasqUnit},
		{"isc", func() { cfg.DHCP.Provider = "isc-dhcp-server" }, NewISCDHCP(r).Apply, NewISCDHCP(r).Health, func() string { return iscConfPath }, iscUnit},
		{"kea", func() { cfg.DHCP.Provider = "kea" }, NewKeaDHCP(r).Apply, NewKeaDHCP(r).Health, func() string { return keaConfPath }, keaUnit},
	}
	for _, tc := range providers {
		t.Run(tc.name, func(t *testing.T) {
			tc.selectProvider()
			if err := tc.apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := tc.health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(tc.conf())
			if err != nil {
				t.Fatal(err)
			}
			r.commands = nil
			if err := tc.apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(tc.conf())
			if err != nil {
				t.Fatal(err)
			}
			if !before.ModTime().Equal(after.ModTime()) || hasCommand(r.commands, "systemctl restart "+tc.unit) || hasCommand(r.commands, "daemon-reload") {
				t.Fatalf("clean Apply mutated %s: commands=%v", tc.name, r.commands)
			}
			if err := os.WriteFile(tc.conf(), []byte("corrupt\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := tc.health(context.Background(), cfg); err == nil {
				t.Fatal("corrupt config passed Health")
			}
			r.active[tc.unit] = false
			cfg.DHCP.Enabled = false
			if err := tc.health(context.Background(), cfg); err == nil {
				t.Fatal("stale generated config passed unused Health")
			}
			_ = os.Remove(tc.conf())
			cfg.DHCP.Enabled = true
		})
	}
}

func TestDHCPHealthChecksLeaseFileState(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	cfg := providerTestConfig()

	cfg.DHCP.Provider = "isc-dhcp-server"
	isc := NewISCDHCP(r)
	if err := isc.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(iscLeasePath); err != nil {
		t.Fatal(err)
	}
	if err := isc.Health(context.Background(), cfg); err == nil {
		t.Fatal("missing required ISC lease file passed Health")
	}

	for _, tc := range []struct {
		name     string
		provider string
		lease    func() string
		apply    func(context.Context, *config.Config) error
		health   func(context.Context, *config.Config) error
	}{
		{"dnsmasq", "dnsmasq", func() string { return dnsmasqLeasePath }, NewDnsmasq(r).Apply, NewDnsmasq(r).Health},
		{"kea", "kea", func() string { return keaLeasePath }, NewKeaDHCP(r).Apply, NewKeaDHCP(r).Health},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.DHCP.Provider = tc.provider
			if err := tc.apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(tc.lease(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := tc.health(context.Background(), cfg); err == nil {
				t.Fatal("non-regular lease path passed Health")
			}
		})
	}
}

func TestDNSPlanDetectsLiveFileDrift(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
	if err := m.Unbound.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unboundConfPath, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	actions, err := NewDNS(m).Plan(cfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 || actions[0].Kind != "repair" {
		t.Fatalf("live drift plan = %#v", actions)
	}
}

func TestInvalidCandidateNeverReplacesWorkingProviderConfig(t *testing.T) {
	tests := []struct {
		name      string
		validator string
		configure func(*config.Config)
		path      func() string
		apply     func(*providerRunner) func(context.Context, *config.Config) error
	}{
		{"dnsmasq", "dnsmasq", func(c *config.Config) { c.DHCP.Provider = "dnsmasq" }, func() string { return dnsmasqConfPath }, func(r *providerRunner) func(context.Context, *config.Config) error { return NewDnsmasq(r).Apply }},
		{"isc", "dhcpd", func(c *config.Config) { c.DHCP.Provider = "isc-dhcp-server" }, func() string { return iscConfPath }, func(r *providerRunner) func(context.Context, *config.Config) error { return NewISCDHCP(r).Apply }},
		{"kea", "kea-dhcp4", func(c *config.Config) { c.DHCP.Provider = "kea" }, func() string { return keaConfPath }, func(r *providerRunner) func(context.Context, *config.Config) error { return NewKeaDHCP(r).Apply }},
		{"unbound", "unbound-checkconf", func(c *config.Config) { c.DHCP.Enabled = false; c.DNS.Enabled, c.DNS.Provider = true, "unbound" }, func() string { return unboundConfPath }, func(r *providerRunner) func(context.Context, *config.Config) error { return NewUnbound(r).Apply }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			useProviderPaths(t)
			r := newProviderRunner()
			cfg := providerTestConfig()
			tc.configure(cfg)
			apply := tc.apply(r)
			if err := apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(tc.path())
			if err != nil {
				t.Fatal(err)
			}
			cfg.DNS.LocalDomain = "changed.example"
			cfg.DHCP.AdvancedOptions = "changed-option true"
			cfg.Networks[0].DHCPPool.Start = "192.168.50.101"
			r.failName = tc.validator
			if err := apply(context.Background(), cfg); err == nil {
				t.Fatal("invalid candidate was accepted")
			}
			after, err := os.ReadFile(tc.path())
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("working config was replaced on validation failure")
			}
		})
	}
}

func TestProviderSwitchPreflightFailsBeforeStoppingWorkingDaemon(t *testing.T) {
	t.Run("dhcp", func(t *testing.T) {
		useProviderPaths(t)
		r := newProviderRunner()
		r.active[dnsmasqUnit] = true
		r.failName = "kea-dhcp4"
		cfg := providerTestConfig()
		cfg.DHCP.Provider = "kea"
		if err := NewDHCP(NewManager(r)).Apply(context.Background(), cfg); err == nil {
			t.Fatal("invalid Kea candidate was accepted")
		}
		if !r.active[dnsmasqUnit] || hasCommand(r.commands, "systemctl stop "+dnsmasqUnit) {
			t.Fatalf("old DHCP daemon was stopped before preflight: %v", r.commands)
		}
	})
	t.Run("dns", func(t *testing.T) {
		useProviderPaths(t)
		r := newProviderRunner()
		r.active[dnsproxyUnit] = true
		r.failName = "unbound-checkconf"
		cfg := providerTestConfig()
		cfg.DHCP.Enabled = false
		cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
		if err := NewDNS(NewManager(r)).Apply(context.Background(), cfg); err == nil {
			t.Fatal("invalid Unbound candidate was accepted")
		}
		if !r.active[dnsproxyUnit] || hasCommand(r.commands, "systemctl stop "+dnsproxyUnit) {
			t.Fatalf("old DNS daemon was stopped before preflight: %v", r.commands)
		}
	})
}

func TestDHCPLifecycleAllProvidersAndDisabled(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "isc-dhcp-server", "kea"} {
		t.Run(provider, func(t *testing.T) {
			useProviderPaths(t)
			r := newProviderRunner()
			m := NewManager(r)
			cfg := providerTestConfig()
			cfg.DHCP.Provider = provider
			s := NewDHCP(m)
			if s.Name() != "dhcp" {
				t.Fatalf("Name = %q", s.Name())
			}
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			actions, err := s.Plan(cfg, cfg)
			if err != nil || len(actions) != 0 {
				t.Fatalf("clean Plan = %#v, %v", actions, err)
			}
			off := *cfg
			off.DHCP.Enabled = false
			actions, err = s.Plan(cfg, &off)
			if err != nil || len(actions) != 1 || actions[0].Kind != "delete" {
				t.Fatalf("disable Plan = %#v, %v", actions, err)
			}
			if err := s.Apply(context.Background(), &off); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), &off); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDNSLifecycleAllProvidersWithoutSystemCapture(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "unbound", "dnsproxy"} {
		t.Run(provider, func(t *testing.T) {
			useProviderPaths(t)
			r := newProviderRunner()
			m := NewManager(r)
			m.Resolv.Root = t.TempDir()
			cfg := providerTestConfig()
			cfg.DHCP.Enabled = false
			cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, provider, 5353
			s := NewDNS(m)
			if s.Name() != "dns" {
				t.Fatalf("Name = %q", s.Name())
			}
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			actions, err := s.Plan(cfg, cfg)
			if err != nil || len(actions) != 0 {
				t.Fatalf("clean Plan = %#v, %v", actions, err)
			}
			off := *cfg
			off.DNS.Enabled = false
			if err := s.Apply(context.Background(), &off); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), &off); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDisabledPlansDetectStaleProviderRuntime(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled = false
	r.active[iscUnit] = true
	actions, err := NewDHCP(m).Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "repair" {
		t.Fatalf("disabled DHCP stale Plan = %#v, %v", actions, err)
	}
	r.active[iscUnit] = false
	r.active[unboundUnit] = true
	actions, err = NewDNS(m).Plan(cfg, cfg)
	if err != nil || len(actions) == 0 || actions[0].Kind != "repair" {
		t.Fatalf("disabled DNS stale Plan = %#v, %v", actions, err)
	}
}

func TestUnboundDNSSECAnchorLifecycleAndHealth(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.DNSSEC = true, "unbound", true
	u := NewUnbound(r)
	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unboundAnchorPath); err != nil {
		t.Fatalf("DNSSEC anchor: %v", err)
	}
	if err := u.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if hasCommand(r.commands, "unbound-anchor") || hasCommand(r.commands, "systemctl restart "+unboundUnit) {
		t.Fatalf("clean DNSSEC Apply mutated state: %v", r.commands)
	}
	if err := os.Remove(unboundAnchorPath); err != nil {
		t.Fatal(err)
	}
	if err := u.Health(context.Background(), cfg); err == nil {
		t.Fatal("missing DNSSEC anchor passed Health")
	}
}

func TestUnboundTrustAnchorRejectsUnsafeObjectsAndRepairsEmptyFile(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	u := NewUnbound(r)
	if err := os.WriteFile(unboundAnchorPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trustAnchorHealth(unboundAnchorPath); err == nil {
		t.Fatal("empty trust anchor passed health")
	}
	if err := u.ensureTrustAnchor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := trustAnchorHealth(unboundAnchorPath); err != nil {
		t.Fatalf("repaired trust anchor: %v", err)
	}

	if err := os.Remove(unboundAnchorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(unboundAnchorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := u.ensureTrustAnchor(context.Background()); err == nil || !strings.Contains(err.Error(), "обычный файл") {
		t.Fatalf("directory anchor error=%v", err)
	}
	if hasCommand(r.commands, "unbound-anchor") {
		t.Fatalf("unsafe anchor target was passed to unbound-anchor: %v", r.commands)
	}
	if err := os.Remove(unboundAnchorPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(unboundAnchorPath), "foreign-anchor")
	if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, unboundAnchorPath); err == nil {
		r.commands = nil
		if err := u.ensureTrustAnchor(context.Background()); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink anchor error=%v", err)
		}
		if hasCommand(r.commands, "unbound-anchor") {
			t.Fatalf("symlink anchor was passed to unbound-anchor: %v", r.commands)
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "foreign" {
			t.Fatalf("symlink target changed: %q, %v", data, err)
		}
		if err := os.Remove(unboundAnchorPath); err != nil {
			t.Fatal(err)
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.WriteFile(unboundAnchorPath, []byte("trust-anchor"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unboundAnchorPath, 0o622); err != nil {
			t.Fatal(err)
		}
		if err := trustAnchorHealth(unboundAnchorPath); err == nil || !strings.Contains(err.Error(), "записи") {
			t.Fatalf("writable trust anchor passed health: %v", err)
		}
	}
}

func TestUnboundHealthRunsCheckconfAgainstActiveConfiguration(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
	u := NewUnbound(r)
	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.failName, r.failContains = "unbound-checkconf", unboundConfPath
	if err := u.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "активной конфигурации") {
		t.Fatalf("failed active checkconf passed Health: %v", err)
	}
}
