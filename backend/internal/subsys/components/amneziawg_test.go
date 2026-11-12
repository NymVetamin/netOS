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

// awgRunner models dpkg, apt-cache, apt-get, apt-mark and modprobe.
type awgRunner struct {
	installed map[string]bool
	candidate map[string]string
	modprobe  error
	calls     []string
}

func (r *awgRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "dpkg-query":
		if r.installed[args[len(args)-1]] {
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
		if len(args) > 0 && contains(args, "install") {
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && a != "install" && a != "DPkg::Lock::Timeout=60" {
					r.installed[a] = true
				}
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
		if problem := New(r, testLogger{}).amneziaKernelProblem(context.Background()); problem != "" {
			t.Fatalf("%s: %s", name, problem)
		}
	}
	for name, r := range map[string]*awgRunner{
		"headers gone":   {installed: map[string]bool{}, candidate: map[string]string{headers: "(none)"}},
		"unknown to apt": {installed: map[string]bool{}},
	} {
		problem := New(r, testLogger{}).amneziaKernelProblem(context.Background())
		if !strings.Contains(problem, "требуется обновление ядра Linux") || !strings.Contains(problem, testKernel) {
			t.Fatalf("%s: %q", name, problem)
		}
	}
}

func TestAmneziaWGInstallRefusesWithoutHeaders(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{}}
	s := New(r, testLogger{})
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
	r := &awgRunner{installed: map[string]bool{}, candidate: map[string]string{headers: "6.12.107-1"}}
	s := New(r, testLogger{})
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
	if !r.called("apt-mark auto " + headers) {
		t.Fatal("headers installed for the module would outlive it")
	}
	if !r.called("modprobe amneziawg") {
		t.Fatal("module load was not verified")
	}
	if _, err := os.Stat(system.PolicyRCPath); !os.IsNotExist(err) {
		t.Fatal("daemon hold left behind", err)
	}
}

func TestAmneziaWGKeepsPreinstalledHeadersManual(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{"linux-headers-" + testKernel: true}}
	if err := New(r, testLogger{}).install(context.Background(), awgInfo(t), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if r.called("apt-mark") {
		t.Fatal("headers the administrator installed were marked for autoremoval")
	}
}

func TestAmneziaWGReportsModuleThatDidNotBuild(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{"linux-headers-" + testKernel: true}, modprobe: errors.New("Module amneziawg not found")}
	err := New(r, testLogger{}).install(context.Background(), awgInfo(t), func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "модуль ядра AmneziaWG не загрузился") {
		t.Fatalf("broken module reported as installed: %v", err)
	}
}

func TestAmneziaWGHeadersProtectedOnlyWhileSelected(t *testing.T) {
	awgEnv(t)
	headers := "linux-headers-" + testKernel
	if !protectedComponentPackages(map[string]bool{amneziaWGID: true})[headers] {
		t.Fatal("removing another component would autoremove the module's headers")
	}
	if protectedComponentPackages(map[string]bool{})[headers] {
		t.Fatal("headers would survive AmneziaWG removal")
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
	s := New(r, testLogger{})
	if got := s.Unavailable(context.Background(), map[string]bool{amneziaWGID: true}); len(got) != 0 || len(r.calls) != 0 {
		t.Fatalf("installed component probed: %v %v", got, r.calls)
	}
	if got := s.Unavailable(context.Background(), map[string]bool{}); !strings.Contains(got[amneziaWGID], "требуется обновление ядра Linux") {
		t.Fatalf("missing headers not reported: %v", got)
	}
}
