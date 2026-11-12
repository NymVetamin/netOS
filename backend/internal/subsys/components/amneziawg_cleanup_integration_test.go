//go:build linux

package components

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

type aptCleanupFault struct {
	system.Runner
	fail      bool
	lockPurge bool
}

func (r *aptCleanupFault) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.fail && name == "apt-get" && contains(args, "-s") {
		return "", errors.New("injected cleanup simulation failure")
	}
	if r.lockPurge && name == "apt-get" && contains(args, "purge") && !contains(args, "--autoremove") {
		r.lockPurge = false
		locker := exec.CommandContext(ctx, "python3", "-u", "-c", "import fcntl,time; f=open('/var/lib/dpkg/lock-frontend','w'); fcntl.lockf(f,fcntl.LOCK_EX); print('locked',flush=True); time.sleep(30)")
		pipe, err := locker.StdoutPipe()
		if err != nil {
			return "", err
		}
		if err := locker.Start(); err != nil {
			return "", err
		}
		defer func() { _ = locker.Process.Kill(); _ = locker.Wait() }()
		ready, err := bufio.NewReader(pipe).ReadString('\n')
		if err != nil || ready != "locked\n" {
			return "", fmt.Errorf("dpkg test lock not acquired: %v", err)
		}
		bounded := append([]string(nil), args...)
		for i, value := range bounded {
			if value == "DPkg::Lock::Timeout=60" {
				bounded[i] = "DPkg::Lock::Timeout=1"
			}
		}
		out, err := r.Runner.Run(ctx, name, bounded...)
		if err == nil {
			return out, errors.New("apt ignored real dpkg lock")
		}
		if !strings.Contains(out+err.Error(), "/var/lib/dpkg/lock-frontend") {
			return out, fmt.Errorf("unexpected apt failure instead of lock refusal: %w", err)
		}
		return out, fmt.Errorf("real apt lock refusal: %w", err)
	}
	return r.Runner.Run(ctx, name, args...)
}

// This test purges real AWG packages. It requires an explicitly marked disposable
// VM, not merely root privileges or the ordinary integration-test environment.
func TestIntegrationAmneziaWGCleanupRetry(t *testing.T) {
	if os.Getenv("NETOS_DISPOSABLE_APT_TEST") != "1" {
		t.Skip("disposable apt VM only")
	}
	marker, err := os.ReadFile("/run/netos-disposable-apt-test")
	if os.Geteuid() != 0 || err != nil || string(marker) != "disposable apt test\n" {
		t.Fatal("refusing unmarked host")
	}
	r := &aptCleanupFault{Runner: system.NewExec()}
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	ctx := context.Background()
	for _, pkg := range []string{"amneziawg-dkms", "amneziawg-tools"} {
		if !s.Packages.Installed(ctx, pkg) {
			t.Fatalf("prerequisite not installed: %s", pkg)
		}
	}
	protected, err := s.installedPackageNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delete(protected, "amneziawg-dkms")
	delete(protected, "amneziawg-tools")
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		return string(out)
	}
	// Tiny real packages make the apt Suggests rule deterministic without
	// depending on which compiler/header packages a particular VM image has.
	names := []string{"netos-qa-cleanup-anchor", "netos-qa-cleanup-left", "netos-qa-cleanup-unrelated", "netos-qa-cleanup-protected"}
	for _, name := range names {
		if s.Packages.Installed(ctx, name) {
			t.Fatalf("fixture name already installed: %s", name)
		}
	}
	t.Cleanup(func() {
		var present []string
		for _, name := range names {
			if s.Packages.Installed(ctx, name) {
				present = append(present, name)
			}
		}
		if len(present) > 0 {
			if out, err := exec.Command("apt-get", append([]string{"purge", "-y"}, present...)...).CombinedOutput(); err != nil {
				t.Errorf("fixture cleanup: %v %s", err, out)
			}
		}
	})
	var archives []string
	for i, name := range names {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(filepath.Join(dir, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := fmt.Sprintf("Package: %s\nVersion: 1\nArchitecture: all\nMaintainer: netOS tests <tests@example.invalid>\nDescription: disposable apt cleanup fixture\n", name)
		if i == 0 {
			control += "Suggests: " + strings.Join(names[1:], ", ") + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "DEBIAN", "control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		archive := dir + ".deb"
		run("dpkg-deb", "--build", dir, archive)
		archives = append(archives, archive)
	}
	run("dpkg", append([]string{"-i"}, archives...)...)
	run("apt-mark", append([]string{"auto"}, names[1:]...)...)
	protected[names[0]], protected[names[3]] = true, true
	if err := os.WriteFile(s.amneziaRecord(), []byte("amneziawg-dkms amneziawg-tools\n"+names[1]+"\n"+names[3]+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r.fail = true
	if err := s.removeProtected(ctx, awgInfo(t), protected); err == nil || !strings.Contains(err.Error(), "injected cleanup simulation failure") {
		t.Fatalf("expected failure after real primary purge: %v", err)
	}
	if s.Packages.Installed(ctx, "amneziawg-dkms") || s.Packages.Installed(ctx, "amneziawg-tools") {
		t.Fatal("real primary purge did not finish")
	}
	if !s.Packages.Installed(ctx, names[1]) {
		t.Fatal("fixture did not survive primary autoremove")
	}
	if !s.componentRemovable(ctx, awgInfo(t), protected) {
		t.Fatal("pending cleanup invisible after real primary purge")
	}
	r.fail = false
	r.lockPurge = true
	if err := s.removeProtected(ctx, awgInfo(t), protected); err == nil || !strings.Contains(err.Error(), "real apt lock refusal") {
		t.Fatalf("missing real lock failure: %v", err)
	}
	if !s.Packages.Installed(ctx, names[1]) || !s.componentRemovable(ctx, awgInfo(t), protected) {
		t.Fatal("lock failure lost pending cleanup")
	}
	if err := s.removeProtected(ctx, awgInfo(t), protected); err != nil {
		t.Fatal(err)
	}
	if s.Packages.Installed(ctx, names[1]) {
		t.Fatal("retry left recorded package installed")
	}
	for _, name := range []string{names[0], names[2], names[3], "openssh-server"} {
		if !s.Packages.Installed(ctx, name) {
			t.Fatalf("unrelated/protected package removed: %s", name)
		}
	}
	if s.componentRemovable(ctx, awgInfo(t), protected) {
		t.Fatal("completed cleanup still pending")
	}
	if err := s.removeProtected(ctx, awgInfo(t), protected); err != nil {
		t.Fatal(err)
	}
	t.Log("real apt primary purge, simulation failure, real dpkg lock refusal, targeted cleanup retry and protected/unrelated packages PASS")
}
