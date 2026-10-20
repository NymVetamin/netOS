package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func armorFixture(t *testing.T) {
	t.Helper()
	oldDir, oldProfiles := dhcpArmorDir, dhcpArmorProfiles
	t.Cleanup(func() { dhcpArmorDir, dhcpArmorProfiles = oldDir, oldProfiles })
	dhcpArmorDir = t.TempDir()
	dhcpArmorProfiles = filepath.Join(dhcpArmorDir, "profiles")
	if err := os.Mkdir(filepath.Join(dhcpArmorDir, "local"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range dhcpArmorPolicies() {
		if err := os.WriteFile(filepath.Join(dhcpArmorDir, p.file), []byte("#include <local/"+p.file+">"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dhcpArmorProfiles, []byte("/usr/sbin/dhcpd (enforce)\nkea-dhcp4 (enforce)\nkea-lfc (enforce)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDHCPArmorPreservesLocalPolicyAndRetriesReload(t *testing.T) {
	armorFixture(t)
	ctx := context.Background()
	path := filepath.Join(dhcpArmorDir, "local", "usr.sbin.kea-dhcp4")
	const admin = "# administrator\n/custom/file r,\n"
	if err := os.WriteFile(path, []byte(admin), 0o640); err != nil {
		t.Fatal(err)
	}
	fail, calls := true, 0
	run := func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		if name != "apparmor_parser" || len(args) != 2 || args[0] != "-r" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		if fail {
			return "", errors.New("reload failed")
		}
		return "", nil
	}
	if err := ensureDHCPArmor(ctx, "kea", run); err == nil {
		t.Fatal("reload failure ignored")
	}
	fail = false
	for i := 0; i < 2; i++ {
		if err := ensureDHCPArmor(ctx, "kea", run); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), admin) || strings.Count(string(data), dhcpArmorBegin) != 1 {
		t.Fatalf("local policy damaged: %s", data)
	}
	if calls != 5 {
		t.Fatalf("reload did not retry: %d", calls)
	}
	if err := RemoveDHCPAppArmor(ctx, dhcpArmorDir, dhcpArmorProfiles, run); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != admin {
		t.Fatalf("uninstall damaged administrator policy: %s", data)
	}
	data, err := os.ReadFile(filepath.Join(dhcpArmorDir, "local", "usr.sbin.kea-lfc"))
	if err != nil || len(data) != 0 {
		t.Fatalf("mandatory local include missing or not empty: %s %v", data, err)
	}
}

func TestDHCPArmorFailurePrecedesProviderStop(t *testing.T) {
	useProviderPaths(t)
	armorFixture(t)
	r := newProviderRunner()
	r.active[dnsmasqUnit] = true
	r.failName = "apparmor_parser"
	cfg := providerTestConfig()
	cfg.DHCP.Provider = "kea"
	if err := NewDHCP(NewManager(r)).Apply(context.Background(), cfg); err == nil {
		t.Fatal("AppArmor failure ignored")
	}
	if !r.active[dnsmasqUnit] {
		t.Fatal("working DHCP stopped before permissions were ready")
	}
}

func TestDHCPArmorAbsentAndRestrictedRules(t *testing.T) {
	oldDir := dhcpArmorDir
	dhcpArmorDir = t.TempDir()
	defer func() { dhcpArmorDir = oldDir }()
	run := func(context.Context, string, ...string) (string, error) {
		t.Fatal("must not run parser without profiles")
		return "", nil
	}
	if err := ensureDHCPArmor(context.Background(), "kea", run); err != nil {
		t.Fatal(err)
	}
	policies := dhcpArmorPolicies()
	if strings.Contains(policies[2].rules, "netos-validate") || strings.Contains(policies[0].rules, "/**") {
		t.Fatal("unnecessary file access")
	}
	if !strings.Contains(policies[0].rules, "."+filepath.Base(iscConfPath)+".netos-validate-*") {
		t.Fatal("ISC validator path missing")
	}
	if !strings.Contains(policies[1].rules, filepath.ToSlash(keaLeasePath)+"*") ||
		!strings.Contains(policies[2].rules, filepath.ToSlash(keaLeasePath)+"*") {
		t.Fatal("Kea or LFC lease access missing")
	}
	if !strings.Contains(policies[1].rules, "owner /run/kea/logger_lockfile rwk,") {
		t.Fatal("Kea runtime log lock access missing")
	}
	if !strings.Contains(policies[1].rules, "capability dac_override,") ||
		!strings.Contains(policies[2].rules, "capability dac_override,") {
		t.Fatal("root Kea services cannot traverse package-owned lease directory")
	}
	if !strings.Contains(policies[1].rules, "capability dac_read_search,") ||
		!strings.Contains(policies[2].rules, "capability dac_read_search,") {
		t.Fatal("read-only traversal generates denied fallback audits")
	}
}
