package services

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestDebian12KeaProfilesWithoutLocalInclude(t *testing.T) {
	armorFixture(t)
	ctx := context.Background()
	original := map[string]string{}
	for _, p := range dhcpArmorPolicies()[1:] {
		original[p.file] = "abi <abi/3.0>,\ninclude <tunables/global>\n\nprofile " + p.name + " /usr/sbin/" + p.name + " {\n  # administrator policy retained\n  /etc/kea/** r,\n}\n"
		if err := os.WriteFile(filepath.Join(dhcpArmorDir, p.file), []byte(original[p.file]), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dhcpArmorDir, "local", p.file), []byte("/previously/inactive r,\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	run := func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	for i := 0; i < 2; i++ {
		if err := ensureDHCPArmor(ctx, "kea", run); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range dhcpArmorPolicies()[1:] {
		data, _ := os.ReadFile(filepath.Join(dhcpArmorDir, p.file))
		base, _, err := stripDHCPArmor(string(data))
		if err != nil || base != original[p.file] || strings.Count(string(data), dhcpArmorBegin) != 1 {
			t.Fatal("legacy profile damaged or rules duplicated")
		}
		if !strings.Contains(string(data), p.rules) || strings.Contains(string(data), "<local/") {
			t.Fatal("rules missing or inactive local policy enabled")
		}
		if strings.Index(string(data), dhcpArmorEnd) > strings.LastIndex(string(data), "\n}") {
			t.Fatal("rules outside profile")
		}
	}
	if err := RemoveDHCPAppArmor(ctx, dhcpArmorDir, dhcpArmorProfiles, run); err != nil {
		t.Fatal(err)
	}
	for _, p := range dhcpArmorPolicies()[1:] {
		data, _ := os.ReadFile(filepath.Join(dhcpArmorDir, p.file))
		if string(data) != original[p.file] {
			t.Fatal("legacy profile not restored byte-for-byte")
		}
		local, _ := os.ReadFile(filepath.Join(dhcpArmorDir, "local", p.file))
		if string(local) != "/previously/inactive r,\n" {
			t.Fatal("administrator local policy changed")
		}
	}
	if calls != 6 {
		t.Fatalf("unexpected reload count %d", calls)
	}
}

func TestDHCPArmorRejectsUnknownProfileWithoutInclude(t *testing.T) {
	armorFixture(t)
	path := filepath.Join(dhcpArmorDir, "usr.sbin.kea-dhcp4")
	const custom = "profile custom /usr/sbin/kea-dhcp4 {\n}\n"
	if err := os.WriteFile(path, []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context, string, ...string) (string, error) {
		t.Fatal("unsupported profile must be rejected before reload")
		return "", nil
	}
	if err := ensureDHCPArmor(context.Background(), "kea", run); err == nil {
		t.Fatal("unknown layout accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != custom {
		t.Fatal("unknown profile rewritten")
	}
}

// Optional Linux integration: point this at extracted Debian package profiles.
// Parse the real policies without replacing any kernel policy.
func TestDHCPArmorPackageProfileRoundTrip(t *testing.T) {
	fixture := os.Getenv("NETOS_APPARMOR_PROFILE_FIXTURE")
	if runtime.GOOS != "linux" || fixture == "" {
		t.Skip("requires Linux apparmor_parser and extracted package profiles")
	}
	armorFixture(t)
	originals := map[string][]byte{}
	for _, p := range dhcpArmorPolicies()[1:] {
		data, err := os.ReadFile(filepath.Join(fixture, p.file))
		if err != nil {
			t.Fatal(err)
		}
		originals[p.file] = data
		if err := os.WriteFile(filepath.Join(dhcpArmorDir, p.file), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, "-Q", "-I", dhcpArmorDir, "-I", "/etc/apparmor.d", args[1])
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for i := 0; i < 2; i++ {
		if err := ensureDHCPArmor(context.Background(), "kea", run); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveDHCPAppArmor(context.Background(), dhcpArmorDir, dhcpArmorProfiles, run); err != nil {
		t.Fatal(err)
	}
	for file, want := range originals {
		got, err := os.ReadFile(filepath.Join(dhcpArmorDir, file))
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s did not round trip: %v", file, err)
		}
	}
}
