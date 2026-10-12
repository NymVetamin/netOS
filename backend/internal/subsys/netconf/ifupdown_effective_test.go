package netconf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ifupdownQueryRunner struct {
	*backendUnitRunner
	listed string
}

func (r *ifupdownQueryRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "ifquery" {
		return r.listed, nil
	}
	return r.backendUnitRunner.Run(ctx, name, args...)
}

func TestIfupdownMigratesExistingConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, main, fragment string }{
		{"main DHCP conflict", "auto eth0\niface eth0 inet dhcp\n", ""},
		{"fragment DHCP conflict", "source interfaces.d/*\n", "auto eth0\niface eth0 inet dhcp\n"},
		{"missing include", "auto lo\niface lo inet loopback\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTemporaryPaths(t)
			oldMain, oldDir := ifupdownMain, ifupdownDir
			ifupdownDir = filepath.Dir(ifupdownPath)
			ifupdownMain = filepath.Join(filepath.Dir(ifupdownDir), "interfaces")
			t.Cleanup(func() { ifupdownMain, ifupdownDir = oldMain, oldDir })
			if err := os.MkdirAll(ifupdownDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ifupdownMain, []byte(tc.main), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.fragment != "" {
				if err := os.WriteFile(filepath.Join(ifupdownDir, "eth0"), []byte(tc.fragment), 0644); err != nil {
					t.Fatal(err)
				}
			}
			r := &ifupdownQueryRunner{newBackendUnitRunner(), "lo\neth0\nbr-lan\nvl-guest\n"}
			cfg := routerConfig()
			cfg.System.NetworkBackend = "ifupdown"
			err := New(r, nil).Apply(context.Background(), cfg)
			if err != nil {
				t.Fatalf("automatic migration failed: %v", err)
			}
			data, err := os.ReadFile(ifupdownMain)
			if err != nil || strings.Contains(string(data), "iface eth0 inet dhcp") {
				t.Fatalf("conflict remains: %s, %v", data, err)
			}
			if err := RestoreIfupdown(""); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(ifupdownMain)
			if err != nil || string(data) != tc.main {
				t.Fatalf("original not restored: %q %v", data, err)
			}
			if tc.fragment != "" {
				data, err = os.ReadFile(filepath.Join(ifupdownDir, "eth0"))
				if err != nil || string(data) != tc.fragment {
					t.Fatalf("fragment not restored: %q %v", data, err)
				}
			}
		})
	}
}

func TestIfupdownHealthDetectsLostInclude(t *testing.T) {
	useTemporaryPaths(t)
	r := &ifupdownQueryRunner{newBackendUnitRunner(), "lo\neth0\nbr-lan\nvl-guest\n"}
	cfg := routerConfig()
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.listed = "lo\n"
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("missing effective include reported healthy")
	}
}
