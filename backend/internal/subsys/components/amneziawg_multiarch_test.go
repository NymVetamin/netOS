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

type multiarchRunner struct {
	*awgRunner
	fail string
}

func (r *multiarchRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "dpkg" && contains(args, "--print-architecture") {
		r.calls = append(r.calls, "dpkg --print-architecture")
		if r.fail == "architecture" {
			return "", errors.New("architecture failure")
		}
		return "amd64\n", nil
	}
	if name == "dpkg-query" && strings.HasPrefix(args[len(args)-1], "-f=") {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		var out strings.Builder
		for pkg, present := range r.installed {
			if !present {
				continue
			}
			if !strings.Contains(args[len(args)-1], "binary:Package") {
				pkg, _, _ = strings.Cut(pkg, ":")
			}
			fmt.Fprintf(&out, "%s\tinstall ok installed\n", pkg)
		}
		return out.String(), nil
	}
	if name == "apt-get" && contains(args, "-s") {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		if r.fail == "simulation" {
			return "", errors.New("simulation failure")
		}
		var out strings.Builder
		for pkg := range r.autoremovable {
			if r.installed[pkg] {
				fmt.Fprintf(&out, "Remv %s [1]\n", strings.TrimSuffix(pkg, ":amd64"))
			}
		}
		return out.String(), nil
	}
	if name == "apt-get" && contains(args, "purge") && r.fail == "purge" {
		return "", errors.New("purge failure")
	}
	return r.awgRunner.Run(ctx, name, args...)
}

func TestAmneziaWGMultiarchCaptureCleanupRetry(t *testing.T) {
	for _, failure := range []string{"", "architecture", "simulation", "purge"} {
		t.Run(failure, func(t *testing.T) {
			awgEnv(t)
			r := &multiarchRunner{awgRunner: &awgRunner{installed: map[string]bool{"libfixture:i386": true}, autoremovable: map[string]bool{"libfixture:amd64": true, "libfixture:i386": true, "unrelated:amd64": true}}}
			s := New(r, testLogger{})
			s.StateDir = t.TempDir()
			ctx := context.Background()
			before, err := s.installedPackageNames(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.beginAmneziaCapture(before); err != nil {
				t.Fatal(err)
			}
			r.installed["libfixture:amd64"] = true
			events := "status: libfixture:amd64: half-configured\nstatus: libfixture:amd64: installed\nstatus: libfixture:i386: installed\n"
			if err = os.WriteFile(filepath.Join(s.amneziaCaptureDir(), "events"), []byte(events), 0600); err != nil {
				t.Fatal(err)
			}
			if err = s.finishAmneziaCapture(); err != nil {
				t.Fatal(err)
			}
			owned, err := system.ReadPackageNames(s.amneziaRecord())
			if err != nil || len(owned) != 1 || !owned["libfixture:amd64"] {
				t.Fatalf("ownership %v %v", owned, err)
			}
			r.installed["unrelated:amd64"] = true
			r.fail = failure
			if failure != "" {
				if err = s.remove(ctx, awgInfo(t)); err == nil {
					t.Fatal("failure hidden")
				}
				if _, err = os.Stat(s.amneziaRecord()); err != nil {
					t.Fatal("lost retry record", err)
				}
				r.fail = ""
			}
			if err = s.remove(ctx, awgInfo(t)); err != nil {
				t.Fatal(err)
			}
			if r.installed["libfixture:amd64"] || !r.installed["libfixture:i386"] || !r.installed["unrelated:amd64"] {
				t.Fatalf("wrong packages after cleanup: %v", r.installed)
			}
			r.calls = nil
			if err = s.remove(ctx, awgInfo(t)); err != nil {
				t.Fatal(err)
			}
			for _, call := range r.calls {
				if strings.HasPrefix(call, "apt-get ") {
					t.Fatalf("repeat ran apt: %s", call)
				}
			}
		})
	}
}

func TestAmneziaWGMultiarchLegacyAndProtected(t *testing.T) {
	for _, test := range []struct {
		name                        string
		record                      []string
		keep                        map[string]bool
		remainNative, remainForeign bool
	}{
		{"legacy native", []string{"libfixture"}, nil, false, true},
		{"explicit foreign", []string{"libfixture:i386"}, nil, true, false},
		{"protected base", []string{"libfixture:amd64", "libfixture:i386"}, map[string]bool{"libfixture": true}, true, true},
		{"protected foreign", []string{"libfixture:amd64", "libfixture:i386"}, map[string]bool{"libfixture:i386": true}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := &multiarchRunner{awgRunner: &awgRunner{installed: map[string]bool{"libfixture:amd64": true, "libfixture:i386": true}, autoremovable: map[string]bool{"libfixture:amd64": true, "libfixture:i386": true}}}
			s := New(r, testLogger{})
			if err := s.removeAmneziaLeftovers(context.Background(), test.record, test.keep, nil); err != nil {
				t.Fatal(err)
			}
			if r.installed["libfixture:amd64"] != test.remainNative || r.installed["libfixture:i386"] != test.remainForeign {
				t.Fatalf("wrong architecture removed: %v", r.installed)
			}
		})
	}
}

func BenchmarkAmneziaWGPackageIdentityCleanup(b *testing.B) {
	for _, count := range []int{25, 2500} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := &multiarchRunner{awgRunner: &awgRunner{}}
			s := New(r, testLogger{})
			s.StateDir = b.TempDir()
			info, _ := config.ComponentByID(amneziaWGID)
			names := make([]string, count)
			for i := range names {
				names[i] = fmt.Sprintf("fixture-dep-%d", i)
			}
			record := []byte(strings.Join(names, "\n"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r.installed = map[string]bool{"unrelated:amd64": true}
				r.autoremovable = map[string]bool{}
				for _, name := range names {
					r.installed[name], r.autoremovable[name] = true, true
				}
				r.calls = nil
				if err := os.WriteFile(s.amneziaRecord(), record, 0600); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := s.remove(context.Background(), info); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if len(r.installed) != 1 || !r.installed["unrelated:amd64"] {
					b.Fatal("cleanup result differs", r.installed)
				}
				b.ReportMetric(float64(len(r.calls)), "commands/op")
				b.StartTimer()
			}
		})
	}
}
