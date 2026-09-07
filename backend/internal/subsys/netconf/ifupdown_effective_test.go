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

func TestIfupdownRejectsIneffectiveConfigurationBeforeStartingNetworking(t *testing.T) {
	for _, tc := range []struct{ name, main, fragment, listed, want string }{
		{"main DHCP conflict", "auto eth0\niface eth0 inet dhcp\n", "", "lo\neth0\n", "eth0"},
		{"fragment DHCP conflict", "source interfaces.d/*\n", "auto eth0\niface eth0 inet dhcp\n", "lo\neth0\n", "eth0"},
		{"missing include", "auto lo\niface lo inet loopback\n", "", "lo\n", "не читает"},
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
			r := &ifupdownQueryRunner{newBackendUnitRunner(), tc.listed}
			cfg := routerConfig()
			cfg.System.NetworkBackend = "ifupdown"
			err := New(r, nil).Apply(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe config accepted, error=%v", err)
			}
			for _, cmd := range r.commands {
				if cmd == "systemctl start networking.service" || cmd == "systemctl enable networking.service" {
					t.Fatalf("activated conflicting config: %s", cmd)
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
