package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Allows identical cost/behavior tests against the baseline implementation.
func readCatalogForTest(s *Subsystem, ctx context.Context) (map[string]bool, map[string]string) {
	if combined, ok := any(s).(interface {
		CatalogStatus(context.Context) (map[string]bool, map[string]string)
	}); ok {
		return combined.CatalogStatus(ctx)
	}
	installed := s.Status(ctx)
	return installed, s.Unavailable(ctx, installed)
}

type availabilityRunner struct {
	*awgRunner
	failSnapshot, failPolicy bool
}

func (r *availabilityRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if r.failSnapshot && name == "dpkg-query" && strings.Contains(strings.Join(args, " "), "${Package}") {
		return "", errors.New("snapshot unavailable")
	}
	if r.failPolicy && name == "apt-cache" {
		return "", errors.New("policy unavailable")
	}
	return r.awgRunner.Run(ctx, name, args...)
}
func TestCatalogAvailabilitySharesSnapshotAndStaysFresh(t *testing.T) {
	awgEnv(t)
	original := config.Catalog
	config.Catalog = []config.ComponentInfo{awgInfo(t)}
	t.Cleanup(func() { config.Catalog = original })
	headers := kernelHeadersPackage()
	r := &availabilityRunner{awgRunner: &awgRunner{installed: map[string]bool{}, candidate: map[string]string{}}}
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	for _, phase := range []string{"headers", "candidate", "missing", "policy-error", "headers", "snapshot-error", "installed", "missing"} {
		r.installed = map[string]bool{}
		r.candidate = map[string]string{}
		r.failSnapshot = false
		r.failPolicy = false
		switch phase {
		case "headers":
			r.installed[headers] = true
		case "candidate":
			r.candidate[headers] = "1"
		case "policy-error":
			r.failPolicy = true
		case "snapshot-error":
			r.failSnapshot = true
			r.installed[headers] = true
		case "installed":
			r.installed["amneziawg-dkms"] = true
			r.installed["amneziawg-tools"] = true
		}
		oldInstalled := s.Status(context.Background())
		oldUnavailable := s.Unavailable(context.Background(), oldInstalled)
		r.calls = nil
		installed, unavailable := readCatalogForTest(s, context.Background())
		if !reflect.DeepEqual(installed, oldInstalled) || !reflect.DeepEqual(unavailable, oldUnavailable) {
			t.Fatalf("%s response changed", phase)
		}
		if _, leaked := installed[headers]; leaked {
			t.Fatal("package key leaked to component response")
		}
		if phase != "snapshot-error" {
			queries := 0
			for _, call := range r.calls {
				if strings.HasPrefix(call, "dpkg-query ") {
					queries++
				}
			}
			if queries != 1 {
				t.Fatalf("%s duplicate package inventory: %v", phase, r.calls)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	installed, _ := readCatalogForTest(s, ctx)
	if len(installed) != 0 {
		t.Fatal("cancelled snapshot used")
	}
	config.Catalog = nil // no package-backed entries means there is no snapshot
	legacy := s.Unavailable(context.Background(), s.Status(context.Background()))
	_, empty := readCatalogForTest(s, context.Background())
	if !reflect.DeepEqual(empty, legacy) {
		t.Fatal("empty catalog changed availability")
	}
}

func BenchmarkCatalogPackageSnapshot(b *testing.B) {
	for _, n := range []int{250, 25000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := &awgRunner{installed: map[string]bool{}, candidate: map[string]string{}}
			for i := 0; i < n; i++ {
				r.installed[fmt.Sprintf("fixture-%d", i)] = true
			}
			s := New(r, testLogger{})
			s.StateDir = b.TempDir()
			oldRelease := kernelReleasePath
			kernelReleasePath = filepath.Join(s.StateDir, "kernel-release")
			b.Cleanup(func() { kernelReleasePath = oldRelease })
			if err := os.WriteFile(kernelReleasePath, []byte(testKernel), 0600); err != nil {
				b.Fatal(err)
			}
			r.installed[kernelHeadersPackage()] = true
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.calls = nil
				installed, _ := readCatalogForTest(s, context.Background())
				if installed[amneziaWGID] {
					b.Fatal("fixture unexpectedly installed AWG")
				}
				b.ReportMetric(float64(len(r.calls)), "commands/op")
			}
		})
	}
}
