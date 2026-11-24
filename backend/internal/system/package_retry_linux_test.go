package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInterruptedMultiarchParticipants(t *testing.T) {
	plan := "primary 1 all unpack\nlibshared 2 amd64 unpack\nlibshared 2 arm64 configure\nforeign 1 all configure\nlibshared 2 amd64 configure\nprimary 1 all configure\n"
	events := "processing: configure: foreign\nprocessing: configure: libshared:arm64\nprocessing: upgrade: libshared:amd64\nprocessing: configure: primary\n"
	got, err := packageParticipants(strings.NewReader(plan), strings.NewReader(events), []string{"primary", "libshared:amd64"})
	want := []interruptedPackage{{"libshared", "amd64", "2"}, {"primary", "all", "1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("participants %v, error %v", got, err)
	}
}

func TestRetryInterruptedDebianInstall(t *testing.T) {
	if os.Getenv("NETOS_QA_DISPOSABLE") != "1" || os.Getenv("NETOS_PACKAGE_CGROUP") == "" {
		t.Skip("requires a disposable Debian guest with a delegated cgroup")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	adm := filepath.Join(root, "var/lib/dpkg")
	for _, sub := range []string{"var/lib/dpkg", "etc/apt/apt.conf.d", "etc/apt/sources.list.d", "etc/apt/preferences.d", "var/cache/apt/archives/partial", "var/lib/apt/lists/partial", "var/log/apt"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	command := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %s %v", name, args, out, err)
		}
		return string(out)
	}
	write(filepath.Join(adm, "status"), "", 0644)
	conf := filepath.Join(dir, "apt.conf")
	write(conf, fmt.Sprintf("Dir %q; Dir::State::status %q; Dir::Etc::parts %q; Dir::Etc::main %q; Dir::Log %q; DPkg::Options { %q; %q; }; APT::Sandbox::User \"root\";\n", root, filepath.Join(adm, "status"), filepath.Join(root, "etc/apt/apt.conf.d"), filepath.Join(root, "etc/apt/empty"), filepath.Join(root, "var/log/apt"), "--root="+root, "--force-script-chrootless"), 0644)
	t.Setenv("APT_CONFIG", conf)
	t.Setenv("DPKG_ROOT", root)
	t.Setenv("DPKG_ADMINDIR", adm)
	t.Setenv("DPKG_FORCE", "script-chrootless")
	withTestPolicyPath(t)
	unpack := func(name, version, postinst string) {
		t.Helper()
		pkg := filepath.Join(dir, name+version)
		control := filepath.Join(pkg, "DEBIAN")
		if err := os.MkdirAll(control, 0755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(control, "control"), fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: QA <qa@example.invalid>\nDescription: retry fixture\n", name, version), 0644)
		write(filepath.Join(control, "postinst"), "#!/bin/sh\nset -eu\ntest -n \"$DPKG_ROOT\" && test \"$DPKG_ROOT\" != / || exit 1\n"+postinst+"\n", 0755)
		archive := pkg + ".deb"
		command("dpkg-deb", "--build", pkg, archive)
		command("dpkg", "--root="+root, "--unpack", archive)
	}
	const primary = "netos-qa-first"
	const foreign = "netos-qa-unrelated"
	const script = `echo start >>"$DPKG_ROOT/events"
if test ! -e "$DPKG_ROOT/retry"; then sleep 30; fi
echo end >>"$DPKG_ROOT/events"`
	unpack(primary, "1", script)
	newPackages := func() *Packages {
		r := NewExec()
		r.PackageTimeout = 2 * time.Second
		return &Packages{R: r, OwnershipDir: filepath.Join(dir, "ownership")}
	}
	ctx := context.Background()
	p := newPackages()
	if _, err := p.Ensure(ctx, primary); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected timeout", err)
	}
	path := p.receiptPath("install", []string{primary})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	status := func(pkg string) string { return command("dpkg-query", "--admindir="+adm, "-W", "-f=${Status}", pkg) }
	if got := status(primary); got != "install ok half-configured" {
		t.Fatalf("after timeout: %s", got)
	}
	write(filepath.Join(root, "retry"), "", 0600)
	unpack(foreign, "1", `touch "$DPKG_ROOT/foreign-ran"`)
	for i := 0; i < 2; i++ {
		if _, err := newPackages().EnsureWithRefresh(ctx, func() error { return errors.New("offline") }, primary); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if got := status(primary); got != "install ok installed" {
		t.Fatal(got)
	}
	if got := status(foreign); got != "install ok unpacked" {
		t.Fatal(got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("receipt retained", err)
	}
	if err := p.changePackages(ctx, path, []string{primary}, nil); err != nil {
		t.Fatal("concurrent recovery completed", err)
	}
	// A stale receipt must never configure a replacement version.
	unpack(primary, "2", `touch "$DPKG_ROOT/replacement-ran"`)
	write(path, string(raw), 0600)
	for i := 0; i < 2; i++ {
		if _, err := newPackages().Ensure(ctx, primary); err == nil {
			t.Fatal("accepted a replaced version")
		}
	}
	for _, marker := range []string{"foreign-ran", "replacement-ran"} {
		if _, err := os.Stat(filepath.Join(root, marker)); !os.IsNotExist(err) {
			t.Fatal(marker, err)
		}
	}
}
