package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIKEArmorPreservesLocalPolicyAndCleansUp(t *testing.T) {
	s, _ := newTestSubsystem(t)
	ctx := context.Background()
	for _, p := range ikeArmorProfiles {
		if err := writeFile(filepath.Join(s.AppArmorDir, p), []byte("#include <local/"+p+">\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	local := filepath.Join(s.AppArmorDir, "local", ikeArmorProfiles[0])
	const original = "# administrator rule without final newline\n/custom/file r,"
	if err := writeFile(local, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ensureIKEArmor(ctx); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(local)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), ikeArmorBegin) != 1 || !strings.HasPrefix(string(data), original) {
			t.Fatal("policy overwritten or duplicated")
		}
		if !strings.Contains(string(data), "/run/netos-strongswan/charon.vici") {
			t.Fatal("VICI permission absent")
		}
	}
	for i := 0; i < 2; i++ {
		if err := RemoveIKEv2AppArmor(ctx, s.AppArmorDir, s.AppArmorProfiles, s.Runner.Run); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(local)
	if string(data) != original {
		t.Fatal("administrator policy not restored exactly")
	}
	if _, err := os.Stat(filepath.Join(s.AppArmorDir, "local", ikeArmorProfiles[1])); !os.IsNotExist(err) {
		t.Fatal("new local file retained")
	}
}

func TestIKEArmorFailedFirstApplyRestoresLocalPolicy(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	runner := &vpnServiceRunner{active: map[string]bool{}, s: s, failOn: "systemctl restart " + ikev2Unit, failAt: 1}
	s.Runner = runner
	for _, p := range ikeArmorProfiles {
		if err := writeFile(filepath.Join(s.AppArmorDir, p), []byte("#include <local/"+p+">\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	local := filepath.Join(s.AppArmorDir, "local", ikeArmorProfiles[0])
	const original = "# administrator\n/custom/file r,\n"
	if err := writeFile(local, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, server := ikev2TestConfig()
	if err := s.applyIKEv2(context.Background(), cfg, []config.VPNServer{server}, false); err == nil {
		t.Fatal("expected restart failure")
	}
	data, err := os.ReadFile(local)
	if err != nil || string(data) != original {
		t.Fatal("rollback changed administrator policy")
	}
	if _, err := os.Stat(filepath.Join(s.AppArmorDir, "local", ikeArmorProfiles[1])); !os.IsNotExist(err) {
		t.Fatal("rollback retained generated policy")
	}
}

func TestIKEArmorRejectsIncompleteManagedBlock(t *testing.T) {
	if _, _, err := stripIKEArmor("user rule" + ikeArmorBegin + "broken"); err == nil {
		t.Fatal("incomplete policy silently overwritten")
	}
}

func TestIKEArmorDoesNotEnableUnloadedProfiles(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	if err := os.WriteFile(profiles, []byte("unrelated (enforce)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	if err := reloadIKEArmor(context.Background(), dir, profiles, run); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("unloaded profile enabled")
	}
	if err := os.WriteFile(profiles, []byte("/usr/sbin/swanctl (enforce)\n/usr/sbin/charon-systemd (complain)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloadIKEArmor(context.Background(), dir, profiles, run); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("reloads = %d", calls)
	}
}
