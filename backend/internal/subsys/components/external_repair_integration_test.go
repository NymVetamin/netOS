//go:build linux

package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Only temporary targets are changed. Real official executables and the real
// command runner exercise readiness and repair; cached official archives keep
// the fault cases independent of a second network request.
func TestNetworkExternalRepairAndFailureRecovery(t *testing.T) {
	if os.Getenv("NETOS_NETWORK_INTEGRATION") != "1" {
		t.Skip("NETOS_NETWORK_INTEGRATION=1 is required")
	}
	originalFetch := fetch
	for _, id := range []string{"dnsproxy", "xray"} {
		t.Run(id, func(t *testing.T) {
			original := externalReleases[id]
			rel := original
			rel.Target = filepath.Join(t.TempDir(), id)
			externalReleases[id] = rel
			t.Cleanup(func() { externalReleases[id] = original; fetch = originalFetch })
			archive, err := originalFetch(context.Background(), rel.URL(rel.Version, runtime.GOARCH))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("official archive sha256=%x pinned=%s", sha256.Sum256(archive), rel.SHA256[runtime.GOARCH])
			cached := func(context.Context, string) ([]byte, error) { return archive, nil }
			fetch = cached
			s := New(system.NewExec(), quietLogger{})
			info := config.ComponentInfo{ID: id, External: true}
			install := func() {
				t.Helper()
				if err := s.installExternal(context.Background(), info); err != nil {
					t.Fatal(err)
				}
				if !s.externalCurrent(context.Background(), rel) || !externalOwned(rel) {
					t.Fatal("installed executable is not ready and owned")
				}
			}
			install()
			binary, err := os.ReadFile(rel.Target)
			if err != nil {
				t.Fatal(err)
			}
			version, err := s.Runner.Run(context.Background(), rel.Target, rel.VersionArgs...)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("native version=%q binary sha256=%x", version, sha256.Sum256(binary))
			for _, damage := range []string{"not executable", "corrupt executable"} {
				t.Run(damage, func(t *testing.T) {
					if damage == "not executable" {
						if err := os.Chmod(rel.Target, 0o644); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(rel.Target, []byte("invalid executable\n"), 0o755); err != nil {
						t.Fatal(err)
					}
					if s.externalCurrent(context.Background(), rel) {
						t.Fatal("damaged executable reported ready")
					}
					install()
					got, err := os.ReadFile(rel.Target)
					if err != nil || !bytes.Equal(got, binary) {
						t.Fatal("repair did not restore the exact official executable")
					}
				})
			}
			for _, existing := range []bool{true, false} {
				if existing {
					if err := os.Chmod(rel.Target, 0o644); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Remove(rel.Target); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(externalOwnerPath(rel)); err != nil {
						t.Fatal(err)
					}
				}
				for _, failure := range []string{"download", "checksum"} {
					fetch = func(context.Context, string) ([]byte, error) {
						if failure == "download" {
							return nil, errors.New("injected connection failure")
						}
						return []byte("tampered archive"), nil
					}
					if err := s.installExternal(context.Background(), info); err == nil {
						t.Fatal("installation failure was hidden")
					}
					entries, err := os.ReadDir(filepath.Dir(rel.Target))
					if err != nil {
						t.Fatal(err)
					}
					if existing {
						got, err := os.ReadFile(rel.Target)
						if err != nil || !bytes.Equal(got, binary) {
							t.Fatal("failed repair changed the previous executable")
						}
						stat, err := os.Stat(rel.Target)
						if err != nil || stat.Mode().Perm() != 0o644 || !externalOwned(rel) || len(entries) != 2 {
							t.Fatal("failed repair changed mode/ownership or left partial files")
						}
					} else if len(entries) != 0 {
						t.Fatalf("failed first install left files: %v", entries)
					}
					t.Logf("existing=%v failure=%s: previous state exact, no partial files", existing, failure)
				}
			}
			fetch = cached
			install()
		})
	}
}
