package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const testKernel = "6.12.107+deb13-amd64"

// awgRunner models dpkg, apt-cache, apt-get and modprobe. Installing the
// component also brings `deps`, like apt pulling the compiler for DKMS.
type awgRunner struct {
	installed     map[string]bool
	candidate     map[string]string
	deps          []string
	autoremovable map[string]bool // what apt would remove ignoring suggestions
	modprobe      error
	calls         []string
}

func (r *awgRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "dpkg-query":
		last := args[len(args)-1]
		if strings.HasPrefix(last, "-f=") { // the whole package list
			var b strings.Builder
			for pkg, on := range r.installed {
				if on {
					b.WriteString(pkg + "\tinstall ok installed\n")
				}
			}
			return b.String(), nil
		}
		if r.installed[last] {
			return "install ok installed", nil
		}
		return "", errors.New("not installed")
	case "apt-cache":
		pkg := args[len(args)-1]
		if c, ok := r.candidate[pkg]; ok {
			return pkg + ":\n  Installed: (none)\n  Candidate: " + c + "\n", nil
		}
		return "", nil // apt-cache policy prints nothing for an unknown package
	case "apt-get":
		packages := func(verb string) []string {
			var out []string
			seen := false
			for _, a := range args {
				if a == verb {
					seen = true
				} else if seen && !strings.HasPrefix(a, "-") {
					out = append(out, a)
				}
			}
			return out
		}
		switch {
		case contains(args, "-s"):
			var b strings.Builder
			for pkg := range r.autoremovable {
				if r.installed[pkg] {
					b.WriteString("Remv " + pkg + " [1.0]\n")
				}
			}
			return b.String(), nil
		case contains(args, "install"):
			var events strings.Builder
			loggerPath := ""
			for _, arg := range args {
				if path, ok := strings.CutPrefix(arg, "Dpkg::Options::=--status-logger=cat >> '"); ok {
					loggerPath = strings.ReplaceAll(strings.TrimSuffix(path, "'"), "'\"'\"'", "'")
				}
			}
			for _, pkg := range append(packages("install"), r.deps...) {
				r.installed[pkg] = true
				if loggerPath != "" {
					events.WriteString("processing: install: " + pkg + "\nstatus: " + pkg + ": half-installed\nstatus: " + pkg + ": unpacked\nprocessing: configure: " + pkg + "\nstatus: " + pkg + ": unpacked\nstatus: " + pkg + ": half-configured\nstatus: " + pkg + ": installed\n")
				}
			}
			if loggerPath != "" {
				f, err := os.OpenFile(loggerPath, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					return "", err
				}
				_, err = f.WriteString(events.String())
				closeErr := f.Close()
				if err != nil {
					return "", err
				}
				if closeErr != nil {
					return "", closeErr
				}
			}
		case contains(args, "purge"):
			for _, pkg := range packages("purge") {
				delete(r.installed, pkg)
			}
		}
		return "", nil
	case "modprobe":
		return "", r.modprobe
	}
	return "", nil
}

func (r *awgRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func (r *awgRunner) called(prefix string) bool {
	for _, call := range r.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

func awgEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	list, key, release, policy := amneziaListPath, amneziaKeyPath, kernelReleasePath, system.PolicyRCPath
	amneziaListPath = filepath.Join(dir, "sources.list.d", "netos-amnezia.list")
	amneziaKeyPath = filepath.Join(dir, "keyrings", "netos-amnezia.asc")
	kernelReleasePath = filepath.Join(dir, "osrelease")
	system.PolicyRCPath = filepath.Join(dir, "policy-rc.d")
	t.Cleanup(func() {
		amneziaListPath, amneziaKeyPath, kernelReleasePath, system.PolicyRCPath = list, key, release, policy
	})
	if err := os.WriteFile(kernelReleasePath, []byte(testKernel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newAWG(t *testing.T, r *awgRunner) *Subsystem {
	t.Helper()
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	return s
}

func awgInfo(t *testing.T) config.ComponentInfo {
	t.Helper()
	info, ok := config.ComponentByID(amneziaWGID)
	if !ok {
		t.Fatal("AmneziaWG missing from the catalog")
	}
	return info
}

// The key is the one whose fingerprint was checked against the PPA
// (75C9DD72C799870E310542E24166F2C257290828); any edit must be deliberate.
func TestAmneziaKeyIsThePinnedPPAKey(t *testing.T) {
	sum := sha256.Sum256([]byte(amneziaKey))
	if got := hex.EncodeToString(sum[:]); got != "c6f90414e6810886cdbc4fe49d8d877d7ed892e9933a559d28d327a226711331" {
		t.Fatalf("embedded Amnezia key changed: %s", got)
	}
	if !strings.Contains(amneziaList, "signed-by=/etc/apt/keyrings/netos-amnezia.asc") {
		t.Fatal("source is not bound to the pinned key")
	}
}

func TestAmneziaKernelProblem(t *testing.T) {
	awgEnv(t)
	headers := "linux-headers-" + testKernel
	for name, r := range map[string]*awgRunner{
		"headers installed":  {installed: map[string]bool{headers: true}},
		"headers in archive": {installed: map[string]bool{}, candidate: map[string]string{headers: "6.12.107-1"}},
	} {
		if problem := newAWG(t, r).amneziaKernelProblem(context.Background()); problem != "" {
			t.Fatalf("%s: %s", name, problem)
		}
	}
	for name, r := range map[string]*awgRunner{
		"headers gone":   {installed: map[string]bool{}, candidate: map[string]string{headers: "(none)"}},
		"unknown to apt": {installed: map[string]bool{}},
	} {
		problem := newAWG(t, r).amneziaKernelProblem(context.Background())
		if !strings.Contains(problem, "требуется обновление ядра Linux") || !strings.Contains(problem, testKernel) {
			t.Fatalf("%s: %q", name, problem)
		}
	}
}

func TestAmneziaWGInstallRefusesWithoutHeaders(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{}}
	s := newAWG(t, r)
	refreshed := 0
	err := s.install(context.Background(), awgInfo(t), func() error { refreshed++; return nil })
	if err == nil || !strings.Contains(err.Error(), "требуется обновление ядра Linux") {
		t.Fatalf("install did not refuse: %v", err)
	}
	if refreshed == 0 {
		t.Fatal("kernel check used stale apt lists")
	}
	if r.called("apt-get -o DPkg::Lock::Timeout=60 install") || r.called("modprobe") {
		t.Fatalf("refused install still changed packages: %v", r.calls)
	}
}

func TestAmneziaWGInstallAddsRepoHeadersAndLoadsModule(t *testing.T) {
	awgEnv(t)
	headers := "linux-headers-" + testKernel
	r := &awgRunner{installed: map[string]bool{"libdpkg-perl": true}, candidate: map[string]string{headers: "6.12.107-1"}, deps: []string{"gcc-14"}}
	s := newAWG(t, r)
	if err := s.install(context.Background(), awgInfo(t), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(amneziaKeyPath); err != nil || string(data) != amneziaKey {
		t.Fatal("pinned key not written", err)
	}
	if data, err := os.ReadFile(amneziaListPath); err != nil || string(data) != amneziaList {
		t.Fatal("repository not written", err)
	}
	for _, pkg := range []string{headers, "amneziawg-dkms", "amneziawg-tools"} {
		if !r.installed[pkg] {
			t.Fatalf("%s not installed: %v", pkg, r.calls)
		}
	}
	// Everything this installation brought is recorded for removal.
	if got := strings.Join(s.readAmneziaRecord(), " "); got != "amneziawg-dkms amneziawg-tools gcc-14 "+headers {
		t.Fatalf("recorded packages: %q", got)
	}
	if !r.called("modprobe amneziawg") {
		t.Fatal("module load was not verified")
	}
	if _, err := os.Stat(system.PolicyRCPath); !os.IsNotExist(err) {
		t.Fatal("daemon hold left behind", err)
	}
}

func TestAmneziaWGLeavesPreinstalledHeaders(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{"linux-headers-" + testKernel: true}}
	s := newAWG(t, r)
	if err := s.install(context.Background(), awgInfo(t), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, name := range s.readAmneziaRecord() {
		if strings.HasPrefix(name, "linux-headers-") {
			t.Fatal("headers the administrator installed would be purged with the component")
		}
	}
}

func TestAmneziaWGReportsModuleThatDidNotBuild(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{"linux-headers-" + testKernel: true}, modprobe: errors.New("Module amneziawg not found")}
	err := newAWG(t, r).install(context.Background(), awgInfo(t), func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "модуль ядра AmneziaWG не загрузился") {
		t.Fatalf("broken module reported as installed: %v", err)
	}
}

func TestAmneziaWGRemovalPurgesWhatItBroughtOnly(t *testing.T) {
	awgEnv(t)
	headers := "linux-headers-" + testKernel
	for name, recorded := range map[string]string{
		"brought by netOS":    "amneziawg-dkms amneziawg-tools gcc-14 " + headers,
		"administrator's own": "amneziawg-dkms amneziawg-tools",
	} {
		// gcc-14 stays after purge --autoremove: libdpkg-perl suggests a compiler.
		r := &awgRunner{installed: map[string]bool{headers: true, "gcc-14": true, "libdpkg-perl": true, "amneziawg-dkms": true, "amneziawg-tools": true},
			autoremovable: map[string]bool{"gcc-14": true, "unrelated-auto": true}}
		r.installed["unrelated-auto"] = true
		s := newAWG(t, r)
		if err := os.WriteFile(s.amneziaRecord(), []byte(recorded+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.remove(context.Background(), awgInfo(t)); err != nil {
			t.Fatal(err)
		}
		owned := strings.Contains(recorded, headers)
		if r.installed[headers] == owned || r.installed["gcc-14"] == owned {
			t.Fatalf("%s: headers installed=%v gcc installed=%v", name, r.installed[headers], r.installed["gcc-14"])
		}
		if !r.installed["unrelated-auto"] || !r.installed["libdpkg-perl"] {
			t.Fatalf("%s: removal touched packages it did not bring", name)
		}
		if _, err := os.Stat(s.amneziaRecord()); !os.IsNotExist(err) {
			t.Fatalf("%s: record left behind", name)
		}
		unload, purge := -1, -1
		for i, call := range r.calls {
			if call == "modprobe -r amneziawg" && unload < 0 {
				unload = i
			}
			if strings.HasPrefix(call, "apt-get") && strings.Contains(call, " purge ") && purge < 0 {
				purge = i
			}
		}
		if unload < 0 || unload > purge {
			t.Fatal("module must be unloaded before its files are purged")
		}
	}
}

func TestAmneziaRepoFollowsSelection(t *testing.T) {
	awgEnv(t)
	if err := ensureAmneziaRepo(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(amneziaListPath)
	if err := ensureAmneziaRepo(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.Stat(amneziaListPath); !again.ModTime().Equal(info.ModTime()) {
		t.Fatal("unchanged repository rewritten")
	}
	if err := removeAmneziaRepo(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{amneziaListPath, amneziaKeyPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", path)
		}
	}
	if err := removeAmneziaRepo(); err != nil {
		t.Fatal("repeat removal failed", err)
	}
}

func TestUnavailableSkipsInstalledAmneziaWG(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{}}
	s := newAWG(t, r)
	if got := s.Unavailable(context.Background(), map[string]bool{amneziaWGID: true}); len(got) != 0 || len(r.calls) != 0 {
		t.Fatalf("installed component probed: %v %v", got, r.calls)
	}
	if got := s.Unavailable(context.Background(), map[string]bool{}); !strings.Contains(got[amneziaWGID], "требуется обновление ядра Linux") {
		t.Fatalf("missing headers not reported: %v", got)
	}
}
