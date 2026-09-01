package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The regular suite stays deterministic and offline. This explicit test
// verifies that every pinned upstream asset still exists, matches its SHA-256,
// and contains the expected executable.
func TestNetworkPinnedExternalArchives(t *testing.T) {
	if os.Getenv("NETOS_NETWORK_INTEGRATION") != "1" {
		t.Skip("NETOS_NETWORK_INTEGRATION=1 is required")
	}
	s := New(nil, quietLogger{})
	for id, release := range externalReleases {
		t.Run(id, func(t *testing.T) {
			release.Target = filepath.Join(t.TempDir(), id)
			if err := s.installRelease(context.Background(), id, release); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(release.Target)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("invalid extracted target: mode=%v size=%d", info.Mode(), info.Size())
			}
			data, err := os.ReadFile(release.Target)
			if err != nil {
				t.Fatal(err)
			}
			assertELFMachine(t, data, runtime.GOARCH)

			for _, arch := range []string{"amd64", "arm64"} {
				if arch == runtime.GOARCH {
					continue
				}
				t.Run(arch, func(t *testing.T) {
					archive, err := fetch(context.Background(), release.URL(release.Version, arch))
					if err != nil {
						t.Fatal(err)
					}
					digest := sha256.Sum256(archive)
					if got := hex.EncodeToString(digest[:]); got != release.SHA256[arch] {
						t.Fatalf("SHA-256=%s want %s", got, release.SHA256[arch])
					}
					var binary []byte
					if release.ZIP {
						binary, err = extractZIPFile(archive, release.FileInArchive)
					} else {
						binary, err = extractFile(archive, release.FileInArchive)
					}
					if err != nil {
						t.Fatal(err)
					}
					assertELFMachine(t, binary, arch)
				})
			}
		})
	}
}

func assertELFMachine(t *testing.T, data []byte, arch string) {
	t.Helper()
	if len(data) < 20 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatal("extracted target is not an ELF executable")
	}
	machine := uint16(data[18]) | uint16(data[19])<<8
	wantMachine, ok := map[string]uint16{"amd64": 0x3e, "arm64": 0xb7}[arch]
	if !ok {
		t.Fatal(fmt.Errorf("unsupported test architecture %s", arch))
	}
	if machine != wantMachine {
		t.Fatalf("ELF machine=%#x, want %#x for %s", machine, wantMachine, arch)
	}
}
