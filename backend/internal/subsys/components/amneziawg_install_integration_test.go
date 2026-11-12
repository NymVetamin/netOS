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

type localDebRunner struct {
	system.Runner
	archives     map[string]string
	afterInstall func()
}

func (r *localDebRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "apt-get" && contains(args, "install") {
		args = append([]string(nil), args...)
		for i, arg := range args {
			if file, ok := r.archives[arg]; ok {
				args[i] = file
			}
		}
		out, err := r.Runner.Run(ctx, name, args...)
		if r.afterInstall != nil {
			r.afterInstall()
		}
		return out, err
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestIntegrationAmneziaWGPartialInstallOwnership(t *testing.T) {
	if os.Getenv("NETOS_DISPOSABLE_APT_TEST") != "1" {
		t.Skip("disposable apt VM only")
	}
	marker, err := os.ReadFile("/run/netos-disposable-apt-test")
	if os.Geteuid() != 0 || err != nil || string(marker) != "disposable apt test\n" {
		t.Fatal("refusing unmarked host")
	}
	root := t.TempDir()
	names := []string{"netos-qa-install-dep", "netos-qa-install-primary", "netos-qa-install-unrelated"}
	r := &localDebRunner{Runner: system.NewExec(), archives: map[string]string{}}
	s := New(r, testLogger{})
	s.StateDir = filepath.Join(root, "state")
	ctx := context.Background()
	for _, name := range names {
		if s.Packages.Installed(ctx, name) {
			t.Fatalf("fixture already present: %s", name)
		}
	}
	for _, name := range []string{"amneziawg-dkms", "amneziawg-tools", kernelHeadersPackage()} {
		if !s.Packages.Installed(ctx, name) {
			t.Fatalf("prerequisite missing: %s", name)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		return string(out)
	}
	t.Cleanup(func() {
		// purge accepts the half-configured primary as well as installed deps.
		present, err := s.installedPackageNames(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		var cleanup []string
		for _, name := range names {
			if present[name] {
				cleanup = append(cleanup, name)
			}
		}
		if len(cleanup) == 0 {
			return
		}
		out, err := exec.Command("apt-get", append([]string{"purge", "-y"}, cleanup...)...).CombinedOutput()
		if err != nil {
			t.Errorf("fixture cleanup: %v %s", err, out)
		}
	})
	failPath := filepath.Join(root, "fail-postinst")
	if err := os.WriteFile(failPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(dir, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := fmt.Sprintf("Package: %s\nVersion: 1\nArchitecture: all\nMaintainer: netOS tests <tests@example.invalid>\nDescription: disposable postinst fixture\n", name)
		if i == 1 {
			control += "Depends: " + names[0] + "\n"
			body := "#!/bin/sh\nif test -f '" + failPath + "'; then exit 42; fi\nexit 0\n"
			if err := os.WriteFile(filepath.Join(dir, "DEBIAN", "postinst"), []byte(body), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "DEBIAN", "control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		archive := dir + ".deb"
		run("dpkg-deb", "--build", dir, archive)
		r.archives[name] = archive
	}
	info := config.ComponentInfo{ID: amneziaWGID, Title: "AWG ownership fixture", Packages: names[:2]}
	err = s.installAmneziaWG(ctx, info, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "exit status 100") {
		t.Fatalf("expected native postinst failure: %v", err)
	}
	firstOwned, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil || !firstOwned[names[0]] || !firstOwned[names[1]] {
		t.Fatalf("postinst failure lost dependency/partial ownership: %v %v", firstOwned, err)
	}
	if err := s.remove(ctx, info); err != nil {
		t.Fatal(err)
	}
	r.afterInstall = func() {
		if err := os.Mkdir(s.amneziaRecord(), 0700); err != nil {
			t.Fatal(err)
		}
	}
	err = s.installAmneziaWG(ctx, info, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "exit status 100") || !strings.Contains(err.Error(), "учёт установленных пакетов") {
		t.Fatalf("missing real postinst/capture failure: %v", err)
	}
	state := run("dpkg-query", "-W", "-f=${Status}", names[1])
	if !strings.Contains(state, "half-configured") {
		t.Fatal("postinst did not leave partial package", state)
	}
	if !s.amneziaCapturePending() {
		t.Fatal("native transaction was lost")
	}
	if err := os.Remove(s.amneziaRecord()); err != nil {
		t.Fatal(err)
	}
	// A later manual package must not be inferred from a delayed system diff.
	run("dpkg", "--unpack", r.archives[names[2]])
	if err := s.finishAmneziaCapture(); err != nil {
		t.Fatal(err)
	}
	owned, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil {
		t.Fatal(err)
	}
	if !owned[names[0]] || !owned[names[1]] || owned[names[2]] || owned[kernelHeadersPackage()] {
		t.Fatal("incorrect transaction ownership", owned)
	}
	// Clean the failed primary immediately, without first making it installed.
	if err := s.remove(ctx, info); err != nil {
		t.Fatal(err)
	}
	present, err := s.installedPackageNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if present[names[0]] || present[names[1]] || !present[names[2]] {
		t.Fatal("partial cleanup incorrect")
	}
	if err := os.Remove(failPath); err != nil {
		t.Fatal(err)
	}
	r.afterInstall = nil
	if err := s.installAmneziaWG(ctx, info, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.installAmneziaWG(ctx, info, func() error { return nil }); err != nil {
		t.Fatal("repeat install", err)
	}
	if err := s.remove(ctx, info); err != nil {
		t.Fatal(err)
	}
	t.Log("real postinst failure, half-configured ownership/cleanup, record-write recovery, later foreign package isolation and install/remove retry PASS")
}
