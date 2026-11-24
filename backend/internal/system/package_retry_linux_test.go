package system

import (
	"context"
	"crypto/sha256"
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
	plan := "primary 1 all unpack -\nlibshared 2 amd64 unpack -\nlibshared 2 arm64 configure 1\nforeign 1 all configure 1\nlibshared 2 amd64 configure 1\nprimary 1 all configure 1\n"
	events := "processing: configure: foreign\nprocessing: configure: libshared:arm64\nprocessing: upgrade: libshared:amd64\nprocessing: configure: primary\n"
	got, err := packageParticipants(strings.NewReader(plan), strings.NewReader(events), []string{"primary", "libshared:amd64"})
	want := []interruptedPackage{{"libshared", "amd64", "2"}, {"primary", "all", "1"}}
	if err != nil || !reflect.DeepEqual(got.Started, want) {
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
	build := func(name, version, postinst, dependencies string, triggers ...string) string {
		t.Helper()
		pkg := filepath.Join(dir, name+version)
		control := filepath.Join(pkg, "DEBIAN")
		if err := os.MkdirAll(control, 0755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(control, "control"), fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: QA <qa@example.invalid>\nDescription: retry fixture\n%s", name, version, dependencies), 0644)
		write(filepath.Join(control, "postinst"), "#!/bin/sh\nset -eu\ntest -n \"$DPKG_ROOT\" && test \"$DPKG_ROOT\" != / || exit 1\n"+postinst+"\n", 0755)
		if len(triggers) > 0 {
			write(filepath.Join(control, "triggers"), strings.Join(triggers, "\n")+"\n", 0644)
		}
		archive := pkg + ".deb"
		command("dpkg-deb", "--build", pkg, archive)
		return archive
	}
	unpack := func(name, version, postinst string, triggers ...string) {
		command("dpkg", "--root="+root, "--unpack", build(name, version, postinst, "", triggers...))
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
	t.Run("required trigger", func(t *testing.T) {
		const listener = "netos-qa-listener"
		const provider = "netos-qa-provider"
		const consumer = "netos-qa-consumer"
		const activate = "dpkg-trigger --await netos-qa-event"
		unpack(listener, "2", `echo "$1" >> "$DPKG_ROOT/handler"`, "interest netos-qa-event")
		command("dpkg", "--no-triggers", "--configure", listener)
		unpack(provider, "1", activate)
		unpack(consumer, "1", "exit 0")
		command("dpkg", "--no-triggers", "--configure", provider)
		items := []interruptedPackage{{provider, "all", "1"}, {consumer, "all", "1"}}
		for i := 0; i < 2; i++ {
			if err := p.resumePackages(ctx, items, []string{consumer}); err == nil {
				t.Fatal("ran a foreign handler")
			}
		}
		log := filepath.Join(root, "handler")
		if data, err := os.ReadFile(log); err != nil || string(data) != "configure\n" {
			t.Fatalf("foreign handler %q, %v", data, err)
		}
		items = append(items, interruptedPackage{listener, "all", "2"})
		for i := 0; i < 3; i++ {
			if i == 1 {
				unpack(provider, "1", activate)
			} // Enqueue again inside the real recovery loop.
			if err := p.resumePackages(ctx, items, []string{consumer}); err != nil {
				t.Fatal(err)
			}
		}
		if data, err := os.ReadFile(log); err != nil || string(data) != "configure\ntriggered\ntriggered\n" {
			t.Fatalf("own handler %q, %v", data, err)
		}
		if status(provider) != "install ok installed" || status(foreign) != "install ok unpacked" {
			t.Fatal("unexpected final package state")
		}
	})
	t.Run("remaining archive", func(t *testing.T) {
		const app = "qa-app"
		const dep = "qa-prereq"
		packages := []string{build(app, "1", `echo done >> "$DPKG_ROOT/app-runs"`, "Pre-Depends: qa-middle\n"),
			build("qa-middle", "1", "exit 0", "Pre-Depends: qa-prereq\n"),
			build(dep, "1", `test -e "$DPKG_ROOT/continue" || sleep 30`, "")}
		var index strings.Builder
		for _, path := range packages {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&index, "%s\nFilename: %s\nSize: %d\nSHA256: %x\n\n", strings.TrimSpace(command("dpkg-deb", "-f", path)), filepath.Base(path), len(data), sha256.Sum256(data))
		}
		write(filepath.Join(dir, "Packages"), index.String(), 0644)
		write(filepath.Join(root, "etc/apt/sources.list"), "deb [trusted=yes] file:"+dir+" ./\n", 0644)
		command("apt-get", "update")
		if _, err := p.Ensure(ctx, app); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		rec, err := readPackageReceipt(p.receiptPath("install", []string{app}))
		if err != nil || len(rec.Remaining) != 2 {
			t.Fatalf("remaining %v: %v", rec, err)
		}
		write(filepath.Join(root, "continue"), "", 0600)
		unpack(app, "9", "exit 0")
		for range 2 {
			if _, err := newPackages().Ensure(ctx, app); err == nil || status(dep) != "install ok half-configured" {
				t.Fatal("changed package accepted", err)
			}
		}
		command("dpkg", "--purge", app)
		path := p.receiptPath("install", []string{app})
		// The repository now needs an archive absent from the approved plan.
		narrow := rec
		narrow.Remaining = nil
		for _, a := range rec.Remaining {
			if a.Name == app {
				narrow.Remaining = append(narrow.Remaining, a)
			}
		}
		if err := saveReceipt(path, narrow); err != nil {
			t.Fatal(err)
		}
		if _, err := newPackages().Ensure(ctx, app); err == nil {
			t.Fatal("unapproved archive accepted")
		}
		if out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", "qa-middle").Output(); err == nil && strings.Contains(string(out), "install ok") {
			t.Fatalf("unexpected unpack: %q", out)
		}
		if err := saveReceipt(path, rec); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := newPackages().Ensure(ctx, app); err != nil {
				t.Fatal(err)
			}
		}
		data, err := os.ReadFile(filepath.Join(root, "app-runs"))
		if err != nil || string(data) != "done\n" || status(app) != "install ok installed" || status(dep) != "install ok installed" {
			t.Fatalf("retry %q: %v", data, err)
		}
		if out := command("apt-mark", "showauto", "qa-middle"); strings.TrimSpace(out) != "qa-middle" {
			t.Fatalf("dependency lost auto flag: %q", out)
		}
	})
}
