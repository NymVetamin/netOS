package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

var errAWGPostinst = errors.New("test postinst failure")

type partialInstallRunner struct {
	*awgRunner
	fail           bool
	afterInstall   func()
	failAfterQuery bool
	attempted      bool
}

func TestAmneziaWGCommittedCaptureCleanupResumes(t *testing.T) {
	s := New(&awgRunner{installed: map[string]bool{}}, testLogger{})
	s.StateDir = t.TempDir()
	if err := os.WriteFile(s.amneziaRecord(), []byte("saved-dependency\n"), 0600); err != nil {
		t.Fatal(err)
	}
	completed := s.amneziaCaptureDir() + "-complete"
	if err := os.Mkdir(completed, 0700); err != nil {
		t.Fatal(err)
	}
	// Crash after removing before, but before removing the remaining event file.
	if err := os.WriteFile(filepath.Join(completed, "events"), []byte("status: saved-dependency: installed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !s.amneziaCapturePending() {
		t.Fatal("unfinished cleanup hidden")
	}
	if err := s.finishAmneziaCapture(); err != nil {
		t.Fatal(err)
	}
	if s.amneziaCapturePending() {
		t.Fatal("completed capture not cleaned")
	}
	record, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil || !record["saved-dependency"] {
		t.Fatal("committed ownership lost", err)
	}
	if err := s.finishAmneziaCapture(); err != nil {
		t.Fatal("repeat cleanup", err)
	}
}

func BenchmarkAmneziaWGInstallCapture(b *testing.B) {
	for _, count := range []int{25, 2500} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := &awgRunner{candidate: map[string]string{"linux-headers-" + testKernel: "1"}}
			for i := 0; i < count; i++ {
				r.deps = append(r.deps, fmt.Sprintf("new-dependency-%d", i))
			}
			s := New(r, testLogger{})
			s.StateDir = b.TempDir()
			// Keep repository files inside the benchmark, not the host's /etc.
			oldList, oldKey, oldRelease, oldPolicy := amneziaListPath, amneziaKeyPath, kernelReleasePath, system.PolicyRCPath
			system.PolicyRCPath = s.StateDir + "/policy-rc.d"
			kernelReleasePath = s.StateDir + "/osrelease"
			if err := os.WriteFile(kernelReleasePath, []byte(testKernel), 0600); err != nil {
				b.Fatal(err)
			}
			amneziaListPath, amneziaKeyPath = s.StateDir+"/source.list", s.StateDir+"/key.asc"
			b.Cleanup(func() {
				amneziaListPath, amneziaKeyPath, kernelReleasePath, system.PolicyRCPath = oldList, oldKey, oldRelease, oldPolicy
			})
			info, _ := config.ComponentByID(amneziaWGID)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r.installed = map[string]bool{kernelHeadersPackage(): true}
				for j := 0; j < count; j++ {
					r.installed[fmt.Sprintf("existing-package-%d", j)] = true
				}
				r.calls = nil
				if err := os.Remove(s.amneziaRecord()); err != nil && !os.IsNotExist(err) {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := s.installAmneziaWG(context.Background(), info, func() error { return nil }); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				record, err := system.ReadPackageNames(s.amneziaRecord())
				if err != nil || len(record) != count+2 {
					b.Fatal("capture mismatch", len(record), err)
				}
				b.ReportMetric(float64(len(r.calls)), "commands/op")
				b.StartTimer()
			}
		})
	}
}

func (r *partialInstallRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.failAfterQuery && r.attempted && name == "dpkg-query" && strings.HasPrefix(args[len(args)-1], "-f=") {
		return "", errors.New("test after inventory failure")
	}
	out, err := r.awgRunner.Run(ctx, name, args...)
	if name == "apt-get" && contains(args, "install") {
		r.attempted = true
		if r.afterInstall != nil {
			r.afterInstall()
		}
		if r.fail {
			return out, errAWGPostinst
		}
	}
	return out, err
}

func TestAmneziaWGPartialInstallRecordsDependenciesAndRetry(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "postinst", true: "cancelled"}[cancelled], func(t *testing.T) {
			awgEnv(t)
			headers := "linux-headers-" + testKernel
			r := &partialInstallRunner{awgRunner: &awgRunner{installed: map[string]bool{"preexisting": true}, candidate: map[string]string{headers: "1"}, deps: []string{"gcc-14"}, autoremovable: map[string]bool{"gcc-14": true}}, fail: true}
			s := New(r, testLogger{})
			s.StateDir = t.TempDir()
			if err := os.WriteFile(s.amneziaRecord(), []byte("earlier-dependency\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				r.afterInstall = cancel
			}
			if err := s.install(ctx, awgInfo(t), func() error { return nil }); !errors.Is(err, errAWGPostinst) {
				t.Fatalf("installation error lost: %v", err)
			}
			record, err := system.ReadPackageNames(s.amneziaRecord())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{headers, "gcc-14", "amneziawg-dkms", "amneziawg-tools", "earlier-dependency"} {
				if !record[name] {
					t.Fatalf("missing partial ownership: %s", name)
				}
			}
			if record["preexisting"] {
				t.Fatal("preexisting package adopted")
			}
			if r.called("modprobe amneziawg") {
				t.Fatal("module loaded after failed install")
			}
			r.fail = false
			r.afterInstall = nil
			if err := s.install(context.Background(), awgInfo(t), func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := s.remove(context.Background(), awgInfo(t)); err != nil {
				t.Fatal(err)
			}
			if r.installed[headers] || r.installed["gcc-14"] || !r.installed["preexisting"] {
				t.Fatal("partial install cleanup incorrect", r.installed)
			}
		})
	}
}

func TestAmneziaWGInstallRefusesUnreadablePreviousRecord(t *testing.T) {
	awgEnv(t)
	r := &partialInstallRunner{awgRunner: &awgRunner{installed: map[string]bool{}, candidate: map[string]string{"linux-headers-" + testKernel: "1"}}}
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	if err := os.Mkdir(s.amneziaRecord(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.install(context.Background(), awgInfo(t), func() error { return nil }); err == nil {
		t.Fatal("record error hidden")
	}
	if r.attempted {
		t.Fatal("apt invoked with unreadable ownership")
	}
}

func TestAmneziaWGInstallRetainsBothFailureCauses(t *testing.T) {
	awgEnv(t)
	r := &partialInstallRunner{awgRunner: &awgRunner{installed: map[string]bool{}, candidate: map[string]string{"linux-headers-" + testKernel: "1"}, deps: []string{"gcc-14"}}, fail: true}
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	r.afterInstall = func() {
		if err := os.Mkdir(s.amneziaRecord(), 0700); err != nil {
			t.Fatal(err)
		}
	}
	err := s.install(context.Background(), awgInfo(t), func() error { return nil })
	if !errors.Is(err, errAWGPostinst) || !strings.Contains(err.Error(), "учёт установленных пакетов") {
		t.Fatalf("failure cause lost: %v", err)
	}
	if !s.amneziaCapturePending() {
		t.Fatal("failed capture lost native events")
	}
	if _, all := s.componentState(context.Background(), awgInfo(t)); all {
		t.Fatal("pending capture hidden by installed packages")
	}
	if err := os.Remove(s.amneziaRecord()); err != nil {
		t.Fatal(err)
	}
	r.installed["later-unrelated"] = true
	r.fail = false
	r.afterInstall = nil
	if err := s.install(context.Background(), awgInfo(t), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	record, err := system.ReadPackageNames(s.amneziaRecord())
	if err != nil {
		t.Fatal(err)
	}
	if !record["gcc-14"] || record["later-unrelated"] {
		t.Fatal("capture recovery did not isolate original transaction", record)
	}
	if s.amneziaCapturePending() {
		t.Fatal("completed transaction retained")
	}
}
