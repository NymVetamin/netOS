//go:build linux

package components

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type catalogCostRunner struct {
	system.Runner
	calls map[string]int
}

func (r *catalogCostRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls[name]++
	return r.Runner.Run(ctx, name, args...)
}
func TestIntegrationCatalogAvailabilityCost(t *testing.T) {
	if os.Getenv("NETOS_CATALOG_MEASURE") != "1" {
		t.Skip("explicit disposable catalog measurement only")
	}
	marker, err := os.ReadFile("/run/netos-disposable-apt-test")
	if err != nil || string(marker) != "disposable apt test\n" {
		t.Fatal("refusing unmarked host")
	}
	// Read actual dpkg/systemd/apt, with an absent fixture package in the catalog;
	// do not uninstall AWG or modify the host package database for a measurement.
	original := config.Catalog
	config.Catalog = append([]config.ComponentInfo(nil), original...)
	for i := range config.Catalog {
		if config.Catalog[i].ID == amneziaWGID {
			config.Catalog[i].Packages = []string{"netos-qa-catalog-absent"}
		}
	}
	defer func() { config.Catalog = original }()
	r := &catalogCostRunner{Runner: system.NewExec()}
	s := New(r, testLogger{})
	s.StateDir = t.TempDir()
	oldRelease := kernelReleasePath
	defer func() { kernelReleasePath = oldRelease }()
	for _, missing := range []bool{false, true} {
		kernelReleasePath = oldRelease
		if missing {
			kernelReleasePath = filepath.Join(s.StateDir, "missing-kernel")
			if err := os.WriteFile(kernelReleasePath, []byte("netos-qa-unavailable"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 6; i++ {
			r.calls = map[string]int{}
			start := time.Now()
			installed, unavailable := readCatalogForTest(s, context.Background())
			elapsed := time.Since(start)
			if installed[amneziaWGID] || (unavailable[amneziaWGID] != "") != missing {
				t.Fatal("unexpected catalog result", installed, unavailable)
			}
			t.Logf("missing_headers=%v run=%d wall_ms=%.3f commands=%v", missing, i, float64(elapsed)/float64(time.Millisecond), r.calls)
		}
	}
	fmt.Fprintln(os.Stdout, "native catalog snapshots/availability PASS")
}
