package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func cleanupL2TPFixture(t *testing.T) (*Subsystem, config.VPNServer) {
	t.Helper()
	previous := l2tpChapSecrets
	l2tpChapSecrets = filepath.Join(t.TempDir(), "chap-secrets")
	t.Cleanup(func() { l2tpChapSecrets = previous })
	r := vpnRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", nil
		}
		return "", nil
	})
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	s.PreUpDir = t.TempDir()
	server := config.VPNServer{Type: "l2tp", Index: 7}
	if err := s.writeOwned([]ownedServer{{Name: resourceName(server), Type: "l2tp", Index: 7, Unit: l2tpUnitName(server)}}); err != nil {
		t.Fatal(err)
	}
	return s, server
}

func checkL2TPCleanupWriteFailure(t *testing.T, blockWrite func(string) func()) {
	t.Helper()
	s, server := cleanupL2TPFixture(t)
	foreign := "# unrelated\nother * fixture *\n"
	original := foreign + l2tpChapBlock(server)
	if err := os.WriteFile(l2tpChapSecrets, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	unblock := blockWrite(l2tpChapSecrets)
	ctx := context.Background()
	if err := s.Apply(ctx, config.Default()); err == nil {
		t.Fatal("Apply hid CHAP replacement failure")
	}
	owned, err := s.readOwned()
	if err != nil || len(owned) != 1 {
		t.Fatal("failure lost ownership", err)
	}
	data, err := os.ReadFile(l2tpChapSecrets)
	if err != nil || string(data) != original {
		t.Fatal("failure changed original CHAP file", err)
	}
	unblock()
	for range 2 {
		if err := s.Apply(ctx, config.Default()); err != nil {
			t.Fatal(err)
		}
		data, err = os.ReadFile(l2tpChapSecrets)
		if err != nil || string(data) != foreign {
			t.Fatal("retry damaged foreign entries or retained owned block", err)
		}
		owned, err = s.readOwned()
		if err != nil || len(owned) != 0 {
			t.Fatal("retry retained ownership", err)
		}
	}
}

func TestL2TPCleanupReadParseAndMissing(t *testing.T) {
	for _, mode := range []string{"read", "parse", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s, server := cleanupL2TPFixture(t)
			if mode == "read" {
				if err := os.Mkdir(l2tpChapSecrets, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "parse" {
				if err := os.WriteFile(l2tpChapSecrets, []byte("# BEGIN "+l2tpAuthName(server)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := s.Apply(context.Background(), config.Default())
			if (err == nil) != (mode == "missing") {
				t.Fatalf("mode %s unexpected success/error: %v", mode, err)
			}
			if err != nil && !strings.Contains(err.Error(), "chap-secrets") {
				t.Fatal("missing CHAP context", err)
			}
			owned, readErr := s.readOwned()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if mode != "missing" && len(owned) != 1 {
				t.Fatal("lost ownership after failure")
			}
			if mode == "missing" && len(owned) != 0 {
				t.Fatal("missing CHAP file prevented cleanup")
			}
		})
	}
}
