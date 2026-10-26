package components

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type selectedStatusRunner struct {
	commands                           []string
	packages, active, enabled, version string
}

func (r *selectedStatusRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch {
	case name == "dpkg-query":
		return r.packages, nil
	case strings.Contains(command, "list-units"):
		return "dns.service loaded " + r.active + " dead DNS", nil
	case strings.Contains(command, "list-unit-files"):
		return "dns.service " + r.enabled + " enabled", nil
	default:
		return r.version, nil
	}
}
func (r *selectedStatusRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestSelectedStatusPreservesReadinessAndAvoidsUnrelatedWork(t *testing.T) {
	oldCatalog, oldReleases := config.Catalog, externalReleases
	t.Cleanup(func() { config.Catalog = oldCatalog; externalReleases = oldReleases })
	target := filepath.Join(t.TempDir(), "tool")
	externalReleases = map[string]externalRelease{"tool": {Target: target, Version: "v2.0.0", VersionArgs: []string{"version"}}}
	config.Catalog = []config.ComponentInfo{
		{ID: "dns", Packages: []string{"dns", "dns-common"}, Units: []string{"dns.service"}},
		{ID: "tool", External: true},
	}
	r := &selectedStatusRunner{active: "inactive", enabled: "disabled", version: "tool 2.0.0"}
	s := New(r, testLogger{})
	for _, tc := range []struct {
		packages, active, enabled string
		ready                     bool
	}{
		{"", "inactive", "disabled", false},
		{"dns\tinstall ok installed", "inactive", "disabled", false},
		{"dns\tinstall ok installed\ndns-common\tinstall ok installed", "active", "disabled", false},
		{"dns\tinstall ok installed\ndns-common\tinstall ok installed", "inactive", "enabled", false},
		{"dns\tinstall ok installed\ndns-common\tinstall ok installed", "inactive", "disabled", true},
	} {
		r.packages, r.active, r.enabled = tc.packages, tc.active, tc.enabled
		full, selected := s.Status(context.Background()), s.Status(context.Background(), "dns")
		if len(selected) != 1 || selected["dns"] != tc.ready || selected["dns"] != full["dns"] {
			t.Fatalf("readiness changed: full=%v selected=%v", full, selected)
		}
	}
	for _, state := range []string{"missing", "foreign", "old", "ready"} {
		if state != "missing" {
			if err := os.WriteFile(target, []byte("binary"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if state == "old" || state == "ready" {
			if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if state == "old" {
			r.version = "tool 1.0.0"
		} else {
			r.version = "tool 2.0.0"
		}
		full := s.Status(context.Background())
		r.commands = nil
		selected := s.Status(context.Background(), "tool")
		if len(selected) != 1 || selected["tool"] != (state == "ready") || selected["tool"] != full["tool"] {
			t.Fatalf("%s: full=%v selected=%v", state, full, selected)
		}
		for _, command := range r.commands {
			if !strings.HasPrefix(command, target+" ") {
				t.Fatal("unrelated command:", command)
			}
		}
	}
}
