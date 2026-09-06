package netconf

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type missingIfupdownRunner struct {
	*backendUnitRunner
	packages  []string
	installed bool
	fail      bool
}

func (r *missingIfupdownRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "dpkg-query" {
		if r.installed {
			return "install ok installed", nil
		}
		return "", fmt.Errorf("not installed")
	}
	if name == "apt-get" {
		r.packages = append([]string{}, args...)
		if r.fail {
			return "", fmt.Errorf("package download failed")
		}
		r.installed = true
		return "", nil
	}
	return r.backendUnitRunner.Run(ctx, name, args...)
}

func TestReport1953IfupdownDependenciesBeforeMutation(t *testing.T) {
	useTemporaryPaths(t)
	old := system.PolicyRCPath
	system.PolicyRCPath = filepath.Join(t.TempDir(), "policy-rc.d")
	t.Cleanup(func() { system.PolicyRCPath = old })
	cfg := routerConfig()
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "bond", Name: "bond1", Type: "bond", Enabled: true})
	r := &missingIfupdownRunner{backendUnitRunner: newBackendUnitRunner(), fail: true}
	err := New(r, nil).Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "package download failed") {
		t.Fatalf("missing dependency accepted: %v", err)
	}
	for _, pkg := range []string{"ifupdown", "bridge-utils", "ifenslave", "vlan"} {
		if !strings.Contains(strings.Join(r.packages, " "), pkg) {
			t.Errorf("missing package %s: %v", pkg, r.packages)
		}
	}
	for _, cmd := range r.commands {
		if strings.Contains(cmd, " stop ") || strings.Contains(cmd, " mask ") || strings.Contains(cmd, " start ") {
			t.Fatalf("changed networking before dependencies: %s", cmd)
		}
	}
}

func TestReport1953IfupdownInstallsOnce(t *testing.T) {
	useTemporaryPaths(t)
	old := system.PolicyRCPath
	system.PolicyRCPath = filepath.Join(t.TempDir(), "policy-rc.d")
	t.Cleanup(func() { system.PolicyRCPath = old })
	r := &missingIfupdownRunner{backendUnitRunner: newBackendUnitRunner()}
	s := New(r, nil)
	cfg := routerConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !r.installed {
		t.Fatal("did not install dependencies")
	}
	r.packages = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.packages) > 0 {
		t.Fatalf("reinstalled existing packages: %v", r.packages)
	}
}

func TestReport1953BondRenderMatchesDirectMode(t *testing.T) {
	cfg := routerConfig()
	cfg.Interfaces[3].Type = "bond"
	if out := renderIfupdown(cfg); !strings.Contains(out, "bond-mode balance-rr") {
		t.Fatalf("wrong ifupdown bond mode: %s", out)
	}
	cfg.System.NetworkBackend = "networkd"
	out, err := RenderFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "Mode=balance-rr") {
		t.Fatalf("wrong networkd bond mode: %s", out)
	}
}
