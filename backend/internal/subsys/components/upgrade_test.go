package components

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type upgradeRunner struct {
	target   string
	fail     bool
	restarts int
	units    string
}

func (r *upgradeRunner) Run(_ context.Context, n string, a ...string) (string, error) {
	if n == "dpkg-query" {
		return "", nil
	}
	if n == r.target {
		b, e := os.ReadFile(r.target)
		return string(b), e
	}
	if n == "systemctl" {
		switch a[0] {
		case "list-units":
			if r.units != "" {
				return r.units, nil
			}
			return "netos-xray-srv1.service loaded active running Xray\nnetos-socks.service loaded active running SOCKS\nunrelated.service loaded active running other", nil
		case "restart":
			r.restarts++
			if r.fail && r.restarts == 1 {
				return "", fmt.Errorf("activation failed")
			}
			return "", nil
		case "is-active":
			return "active", nil
		}
	}
	return "", fmt.Errorf("unexpected %s %v", n, a)
}
func (r *upgradeRunner) RunInput(ctx context.Context, _ string, n string, a ...string) (string, error) {
	return r.Run(ctx, n, a...)
}
func TestExternalUpgradeAndActivationRollback(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			original := externalReleases
			oldFetch := fetch
			defer func() { externalReleases = original; fetch = oldFetch }()
			target := filepath.Join(t.TempDir(), "xray")
			if err := os.WriteFile(target, []byte("Xray 26.7.28"), 0755); err != nil {
				t.Fatal(err)
			}
			archive := zipArchive(t, "xray", []byte("Xray 26.10.29"))
			sum := sha256.Sum256(archive)
			rel := externalRelease{Version: "v26.10.29", Target: target, VersionArgs: []string{"version"}, ZIP: true, FileInArchive: "xray", SHA256: map[string]string{runtime.GOARCH: fmt.Sprintf("%x", sum)}, URL: func(string, string) string { return "https://example.invalid/xray.zip" }}
			externalReleases = map[string]externalRelease{"xray": rel}
			fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
			if err := os.WriteFile(externalOwnerPath(rel), []byte(externalOwnerMark), 0600); err != nil {
				t.Fatal(err)
			}
			r := &upgradeRunner{target: target, fail: failure}
			s := New(r, testLogger{})
			rows, err := s.CheckUpdates(context.Background(), "xray")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Upgrade(context.Background(), "xray", "stale"); err == nil {
				t.Fatal("stale version accepted")
			}
			if r.restarts != 0 {
				t.Fatal("stale update restarted service")
			}
			err = s.Upgrade(context.Background(), "xray", rows["xray"].Token)
			b, _ := os.ReadFile(target)
			if failure {
				if err == nil || string(b) != "Xray 26.7.28" || r.restarts != 4 {
					t.Fatalf("rollback %s, %v, restarts=%d", b, err, r.restarts)
				}
			} else {
				if err != nil || string(b) != "Xray 26.10.29" || r.restarts != 2 {
					t.Fatalf("upgrade %s, %v, restarts=%d", b, err, r.restarts)
				}
			}
			if _, err := os.Stat(target + ".netos-rollback"); !os.IsNotExist(err) {
				t.Fatal("backup leaked")
			}
			if !externalOwned(rel) {
				t.Fatal("ownership lost")
			}
		})
	}
}
func TestUpdateServiceSelectionIncludesSharedPPP(t *testing.T) {
	var l2tp config.ComponentInfo
	for _, c := range config.Catalog {
		if c.ID == "l2tp" {
			l2tp = c
		}
	}
	r := &upgradeRunner{units: "netos-pppoe-wan1.service loaded active running PPPoE\nnetos-vpn-l2tp-srv1.service loaded active running L2TP\nnetos-unbound.service loaded active running DNS"}
	s := New(r, testLogger{})
	units, err := s.updateUnits(context.Background(), l2tp)
	if err != nil || strings.Join(units, ",") != "netos-pppoe-wan1.service,netos-vpn-l2tp-srv1.service" {
		t.Fatalf("%v, %v", units, err)
	}
}
