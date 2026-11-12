package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type cleanupFaultRunner struct {
	*awgRunner
	failure string
}

func BenchmarkAmneziaWGCleanupRetry(b *testing.B) {
	for _, count := range []int{10, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := &awgRunner{installed: map[string]bool{}, autoremovable: map[string]bool{}}
			s := New(r, testLogger{})
			s.StateDir = b.TempDir()
			info, _ := config.ComponentByID(amneziaWGID)
			var names []string
			for i := 0; i < count; i++ {
				names = append(names, fmt.Sprintf("compiler-fixture-%d", i))
			}
			record := []byte(strings.Join(names, "\n"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				for _, name := range names {
					r.installed[name] = true
					r.autoremovable[name] = true
				}
				r.calls = nil
				if err := os.WriteFile(s.amneziaRecord(), record, 0600); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if !s.componentRemovable(context.Background(), info, nil) {
					b.Fatal("cleanup hidden")
				}
				if err := s.remove(context.Background(), info); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if len(r.installed) != 0 {
					b.Fatal("cleanup incomplete")
				}
				b.ReportMetric(float64(len(r.calls)), "commands/op")
				b.StartTimer()
			}
		})
	}
}

func (r *cleanupFaultRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "apt-get" && ((r.failure == "simulation" && contains(args, "-s")) ||
		(r.failure == "purge" && contains(args, "purge") && !contains(args, "--autoremove"))) {
		return "", errors.New("injected cleanup " + r.failure)
	}
	return r.awgRunner.Run(ctx, name, args...)
}

func TestAmneziaWGCleanupResumesAfterPrimaryPackagesGone(t *testing.T) {
	for _, failure := range []string{"simulation", "purge"} {
		t.Run(failure, func(t *testing.T) {
			awgEnv(t)
			r := &cleanupFaultRunner{awgRunner: &awgRunner{
				installed:     map[string]bool{"amneziawg-dkms": true, "amneziawg-tools": true, "gcc-14": true, "unrelated": true, "protected": true, "needed": true},
				autoremovable: map[string]bool{"gcc-14": true, "unrelated": true, "protected": true},
			}, failure: failure}
			s := New(r, testLogger{})
			s.StateDir = t.TempDir()
			if err := os.WriteFile(s.amneziaRecord(), []byte("amneziawg-dkms amneziawg-tools gcc-14 protected needed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, info, protected := context.Background(), awgInfo(t), map[string]bool{"protected": true}
			if err := s.removeProtected(ctx, info, protected); err == nil {
				t.Fatal("expected cleanup failure")
			}
			if r.installed["amneziawg-dkms"] || r.installed["amneziawg-tools"] {
				t.Fatal("primary purge did not run")
			}
			if !s.componentRemovable(ctx, info, protected) || !s.componentRemovableFrom(ctx, info, protected, componentLiveSnapshot{}, true) {
				t.Fatal("pending cleanup invisible to Apply or snapshot Plan")
			}
			r.failure = ""
			before := len(r.calls)
			if err := s.removeProtected(ctx, info, protected); err != nil {
				t.Fatal(err)
			}
			if r.installed["gcc-14"] {
				t.Fatal("retry kept recorded compiler")
			}
			for _, name := range []string{"unrelated", "protected", "needed"} {
				if !r.installed[name] {
					t.Fatalf("retry removed %s", name)
				}
			}
			for _, call := range r.calls[before:] {
				if strings.Contains(call, "--autoremove") {
					t.Fatalf("retry repeated broad purge: %s", call)
				}
			}
			if _, err := os.Stat(s.amneziaRecord()); !os.IsNotExist(err) {
				t.Fatal("completed record remains", err)
			}
			if s.componentRemovable(ctx, info, protected) {
				t.Fatal("completed cleanup still pending")
			}
			before = len(r.calls)
			if err := s.removeProtected(ctx, info, protected); err != nil {
				t.Fatal(err)
			}
			for _, call := range r.calls[before:] {
				if strings.HasPrefix(call, "apt-get ") {
					t.Fatalf("repeat invoked apt: %s", call)
				}
			}
		})
	}
}

func TestAmneziaWGCleanupResumesHeadersWithoutPrimaryPackages(t *testing.T) {
	awgEnv(t)
	headers := "linux-headers-" + testKernel
	r := &awgRunner{installed: map[string]bool{headers: true}}
	s := newAWG(t, r)
	if err := os.WriteFile(s.amneziaRecord(), []byte(headers), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.remove(context.Background(), awgInfo(t)); err != nil {
		t.Fatal(err)
	}
	if r.installed[headers] {
		t.Fatal("orphan headers not removed")
	}
}

func TestAmneziaWGCleanupRecordReadFailureRemainsVisible(t *testing.T) {
	awgEnv(t)
	r := &awgRunner{installed: map[string]bool{}}
	s := newAWG(t, r)
	if err := os.Mkdir(s.amneziaRecord(), 0700); err != nil {
		t.Fatal(err)
	}
	if !s.componentRemovable(context.Background(), awgInfo(t), nil) {
		t.Fatal("invalid record hidden")
	}
	if err := s.remove(context.Background(), awgInfo(t)); err == nil {
		t.Fatal("record read error swallowed")
	}
	if _, err := os.Stat(s.amneziaRecord()); err != nil {
		t.Fatal("invalid record removed", err)
	}
}
