//go:build linux

package components

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Opt-in package test: only its three empty fixture packages are purged.
func TestIntegrationAmneziaWGMultiarchIdentity(t *testing.T) {
	if os.Getenv("NETOS_N1_MULTIARCH_TEST") != "1" {
		t.Skip("explicit authorized package fixture test only")
	}
	marker, err := os.ReadFile("/run/netos-n1-package-test")
	if os.Geteuid() != 0 || err != nil || string(marker) != "authorized package fixture test\n" {
		t.Fatal("refusing unmarked host")
	}
	for _, existingForeign := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-foreign=%v", existingForeign), func(t *testing.T) {
			testAmneziaWGMultiarchIdentity(t, existingForeign)
		})
	}
}

func testAmneziaWGMultiarchIdentity(t *testing.T, existingForeign bool) {
	ctx := context.Background()
	root := t.TempDir()
	r := &aptCleanupFault{Runner: system.NewExec()}
	s := New(r, testLogger{})
	s.StateDir = filepath.Join(root, "state")
	s.Packages.OwnershipDir = ""
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return string(out)
	}
	native := strings.TrimSpace(run("dpkg", "--print-architecture"))
	foreign := "i386"
	if native == foreign {
		foreign = "amd64"
	}
	base := "netos-qa-n1-multiarch"
	other := "netos-qa-n1-unrelated"
	packages := []string{base + ":" + native, base + ":" + foreign, other + ":" + native}
	for _, name := range []string{base, other, "netos-qa-n1-primary-absent"} {
		if out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", name).CombinedOutput(); err == nil {
			t.Fatalf("fixture already exists: %s %s", name, out)
		}
	}
	foreignBefore := strings.Fields(run("dpkg", "--print-foreign-architectures"))
	added := !contains(foreignBefore, foreign)
	if added {
		run("dpkg", "--add-architecture", foreign)
	}
	t.Cleanup(func() {
		for _, pkg := range packages {
			if _, err := exec.Command("dpkg-query", "-W", "-f=${Status}", pkg).CombinedOutput(); err != nil {
				continue
			}
			if out, err := exec.Command("dpkg", "--purge", pkg).CombinedOutput(); err != nil {
				t.Errorf("fixture cleanup %s: %v %s", pkg, err, out)
			}
		}
		if added {
			if out, err := exec.Command("dpkg", "--remove-architecture", foreign).CombinedOutput(); err != nil {
				t.Errorf("architecture cleanup: %v %s", err, out)
			}
		}
		if out, err := exec.Command("dpkg", "--audit").CombinedOutput(); err != nil || len(out) != 0 {
			t.Errorf("dpkg audit: %v %s", err, out)
		}
	})
	build := func(name, arch string) string {
		t.Helper()
		dir := filepath.Join(root, name+"-"+arch)
		if err := os.MkdirAll(filepath.Join(dir, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := fmt.Sprintf("Package: %s\nVersion: 1\nArchitecture: %s\nMulti-Arch: same\nMaintainer: netOS tests <tests@example.invalid>\nDescription: temporary package identity fixture\n", name, arch)
		if err := os.WriteFile(filepath.Join(dir, "DEBIAN/control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		archive := dir + ".deb"
		run("dpkg-deb", "--build", dir, archive)
		return archive
	}
	foreignDeb := build(base, foreign)
	nativeDeb := build(base, native)
	otherDeb := build(other, native)
	if existingForeign {
		run("dpkg", "-i", foreignDeb)
	}
	before, err := s.installedPackageNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.beginAmneziaCapture(before); err != nil {
		t.Fatal(err)
	}
	run("dpkg", "--status-logger=cat >> "+filepath.Join(s.amneziaCaptureDir(), "events"), "-i", nativeDeb)
	if err = s.finishAmneziaCapture(); err != nil {
		t.Fatal(err)
	}
	owned, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil || !owned[packages[0]] || owned[packages[1]] {
		t.Fatalf("native ownership mismatch: %v %v", owned, err)
	}
	run("dpkg", "-i", otherDeb)
	autoPackages := []string{packages[0], packages[2]}
	if existingForeign {
		autoPackages = append(autoPackages, packages[1])
	}
	run("apt-mark", append([]string{"auto"}, autoPackages...)...)
	// Main AWG packages are deliberately not touched by this scoped test.
	info := config.ComponentInfo{ID: amneziaWGID, Packages: []string{"netos-qa-n1-primary-absent"}}
	r.fail = true
	if err = s.remove(ctx, info); err == nil || !strings.Contains(err.Error(), "simulation failure") {
		t.Fatalf("expected simulation failure: %v", err)
	}
	r.fail = false
	r.lockPurge = true
	if err = s.remove(ctx, info); err == nil || !strings.Contains(err.Error(), "real apt lock refusal") {
		t.Fatalf("expected real lock refusal: %v", err)
	}
	if _, err = os.Stat(s.amneziaRecord()); err != nil {
		t.Fatal("lost ledger after failure", err)
	}
	if err = s.remove(ctx, info); err != nil {
		t.Fatal(err)
	}
	if s.Packages.Installed(ctx, packages[0]) || s.Packages.Installed(ctx, packages[1]) != existingForeign || !s.Packages.Installed(ctx, packages[2]) {
		t.Fatal("removed wrong architecture or unrelated package")
	}
	if err = s.remove(ctx, info); err != nil {
		t.Fatal("repeat", err)
	}
	t.Log("native qualified capture, two architectures, apt native alias, simulation/lock failure, cleanup retry, unrelated packages and repeat PASS")
}
