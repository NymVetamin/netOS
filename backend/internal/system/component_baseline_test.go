package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type componentBaselineRunner struct {
	t            *testing.T
	dir          string
	calls        []string
	live         string
	failDownload bool
	failInstall  bool
}

func (r *componentBaselineRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}
func (r *componentBaselineRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	switch {
	case name == "dpkg-query" && strings.Contains(cmd, "${Conffiles}"):
		return " /etc/kea/kea.conf deadbeef\n /etc/kea/absent.conf abcdef\n", nil
	case name == "dpkg-query":
		return r.live, nil
	case cmd == "apt-mark showauto":
		return "kea-dhcp4-server\n", nil
	case name == "apt-mark":
		return "", nil
	case strings.HasPrefix(cmd, "systemctl is-enabled"):
		return "disabled\n", errors.New("exit 1")
	case strings.HasPrefix(cmd, "systemctl is-active"):
		return "inactive\n", errors.New("exit 3")
	case name == "apt-get" && strings.Contains(cmd, "--download-only"):
		if r.failDownload {
			return "", errors.New("repository unavailable")
		}
		path := filepath.Join(componentSnapshotDir(r.dir), "download", "kea_1.2_amd64.deb")
		return "", os.WriteFile(path, []byte("original binary"), 0600)
	case name == "dpkg-deb":
		return "Package: kea-dhcp4-server\nVersion: 1.2\n", nil
	case name == "apt-get":
		if r.failInstall {
			return "", errors.New("dpkg interrupted")
		}
		r.live = "kea-dhcp4-server\t1.2\tii \n"
		return "", nil
	case name == "tar":
		for i, a := range args {
			if a == "-cpf" {
				return "", os.WriteFile(args[i+1], []byte("original config and local AppArmor"), 0600)
			}
		}
		return "", nil
	}
	r.t.Fatalf("unexpected command %s", cmd)
	return "", nil
}

func baselineFixture(t *testing.T) (string, string, *componentBaselineRunner) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ledger")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "restore-components"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := WritePackageNames(filepath.Join(dir, "initial.txt"), map[string]bool{"kea-dhcp4-server": true, "liboriginal": true}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "kea"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "kea", "kea.conf"), []byte("admin"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &componentBaselineRunner{t: t, dir: dir, live: "kea-dhcp4-server\t1.2\tii \nliboriginal\t2\tii \nnew-netos-package\t1\tii \n"}
	return root, dir, r
}

func TestComponentBaselineCaptureRestoreAndRetry(t *testing.T) {
	withTestPolicyPath(t)
	root, dir, r := baselineFixture(t)
	ctx := context.Background()
	catalog := []BaselineComponent{{ID: "kea", Packages: []string{"kea-dhcp4-server", "new-netos-package"}, Units: []string{"kea-dhcp4-server.service"}}}
	if err := CaptureComponentBaseline(ctx, r, root, dir, catalog); err != nil {
		t.Fatal(err)
	}
	b, err := ReadComponentBaseline(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Packages) != 1 || !b.Packages["kea-dhcp4-server"].Auto || b.Services["kea-dhcp4-server.service"].Enabled != "disabled" {
		t.Fatalf("bad baseline %#v", b)
	}
	for _, cmd := range r.calls {
		if strings.HasPrefix(cmd, "tar ") && strings.Contains(cmd, "etc/apparmor.d ") {
			t.Fatalf("unrelated policies captured: %s", cmd)
		}
	}
	n := len(r.calls)
	r.live = ""
	if err := CaptureComponentBaseline(ctx, r, root, dir, catalog); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != n {
		t.Fatal("capture overwritten on retry")
	}
	r.failInstall = true
	if err := os.WriteFile(filepath.Join(root, "etc", "kea", "absent.conf"), []byte("package default"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreComponentPackages(ctx, r, root, dir, b); err == nil {
		t.Fatal("failed install accepted")
	}
	if _, err := ReadComponentBaseline(dir); err != nil {
		t.Fatal("recovery lost after failure", err)
	}
	r.failInstall = false
	r.calls = nil
	if err := RestoreComponentPackages(ctx, r, root, dir, b); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.calls[0], "tar ") || !strings.Contains(strings.Join(r.calls, "\n"), "apt-mark auto kea-dhcp4-server") {
		t.Fatalf("restore order/auto flag: %v", r.calls)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "kea", "absent.conf")); !os.IsNotExist(err) {
		t.Fatal("originally absent config was not removed")
	}
	r.calls = nil
	if err := RestoreComponentPackages(ctx, r, root, dir, b); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.calls {
		if strings.HasPrefix(cmd, "apt-get ") {
			t.Fatal("already restored package reinstalled")
		}
	}
	if err := os.WriteFile(filepath.Join(componentSnapshotDir(dir), b.Packages["kea-dhcp4-server"].Archive), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadComponentBaseline(dir); err == nil {
		t.Fatal("corrupt binary accepted")
	}
}

func TestComponentBaselineDownloadFailureDoesNotPublishSnapshot(t *testing.T) {
	root, dir, r := baselineFixture(t)
	r.failDownload = true
	err := CaptureComponentBaseline(context.Background(), r, root, dir, []BaselineComponent{{ID: "kea", Packages: []string{"kea-dhcp4-server"}}})
	if err == nil {
		t.Fatal("download failure ignored")
	}
	if b, err := ReadComponentBaseline(dir); err != nil || b != nil {
		t.Fatalf("incomplete baseline published: %v %v", b, err)
	}
}

func TestLegacyComponentStateIsNotInvented(t *testing.T) {
	root, dir, r := baselineFixture(t)
	if err := os.Remove(filepath.Join(dir, "restore-components")); err != nil {
		t.Fatal(err)
	}
	if err := CaptureComponentBaseline(context.Background(), r, root, dir, []BaselineComponent{{ID: "kea", Packages: []string{"kea-dhcp4-server"}}}); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("legacy host adopted as original: %v", r.calls)
	}
}
