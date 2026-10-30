//go:build linux

package components

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Explicit opt-in: this test creates a temporary systemd service, never a
// networking service, and exercises actual Type=simple startup failure.
func TestLiveComponentActivationRollback(t *testing.T) {
	if os.Getenv("NETOS_COMPONENT_UPGRADE_LIVE") != "1" {
		t.Skip("requires authorized systemd test host")
	}
	ctx := context.Background()
	r := system.NewExec()
	unit := fmt.Sprintf("netos-component-update-qa-%d.service", os.Getpid())
	unitPath := filepath.Join("/etc/systemd/system", unit)
	target := filepath.Join(t.TempDir(), "xray")
	old := []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 1.0.0'; exit; fi\nexec sleep infinity\n")
	broken := []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 2.0.0'; exit; fi\nexit 1\n")
	if err := os.WriteFile(target, old, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Unit]\nDescription=netOS component update QA\n[Service]\nType=simple\nExecStart="+target+" run\n"), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = r.Run(ctx, "systemctl", "stop", unit)
		_ = os.Remove(unitPath)
		_, _ = r.Run(ctx, "systemctl", "daemon-reload")
		_, _ = r.Run(ctx, "systemctl", "reset-failed", unit)
	}()
	if _, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(ctx, "systemctl", "start", unit); err != nil {
		t.Fatal(err)
	}
	savedCatalog, savedReleases, savedFetch := config.Catalog, externalReleases, fetch
	defer func() { config.Catalog = savedCatalog; externalReleases = savedReleases; fetch = savedFetch }()
	archive := tarGz(t, "xray", broken)
	sum := sha256.Sum256(archive)
	rel := externalRelease{Version: "v2.0.0", Target: target, VersionArgs: []string{"version"}, FileInArchive: "xray", SHA256: map[string]string{runtime.GOARCH: fmt.Sprintf("%x", sum)}, URL: func(string, string) string { return "https://example.invalid/qa.tar.gz" }}
	config.Catalog = []config.ComponentInfo{{ID: "qa", External: true, RunUnits: []string{unit}}}
	externalReleases = map[string]externalRelease{"qa": rel}
	fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
	if err := os.WriteFile(externalOwnerPath(rel), []byte(externalOwnerMark), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(r, testLogger{})
	rows, err := s.CheckUpdates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, "qa", rows["qa"].Token); err == nil {
		t.Fatal("broken daemon accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != string(old) {
		t.Fatal("old binary not restored")
	}
	if out, err := r.Run(ctx, "systemctl", "is-active", unit); err != nil || out != "active\n" {
		t.Fatalf("old daemon not running: %s %v", out, err)
	}
}
