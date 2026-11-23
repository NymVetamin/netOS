package samba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func writeUnmountVolumes(t testing.TB, volumes []config.StorageVolume) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "samba"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(volumes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "samba", "volumes.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUnmountFreshSnapshotsAndRetry(t *testing.T) {
	volumes := []config.StorageVolume{{ID: "one", UUID: "uuid-one"}, {ID: "two", UUID: "uuid-two"}}
	dir := writeUnmountVolumes(t, volumes)
	paths := []string{MountPath(volumes[0]), MountPath(volumes[1])}
	for _, failure := range []string{"", "findmnt", "umount"} {
		t.Run(failure, func(t *testing.T) {
			mounted := []bool{true, false}
			failed := false
			cause := errors.New("injected failure")
			var calls []string
			run := func(_ context.Context, name string, args ...string) (string, error) {
				if name != "nsenter" || len(args) < 6 || !reflect.DeepEqual(args[:4], []string{"--target", "1", "--mount", "--"}) {
					t.Fatalf("unexpected command: %s %v", name, args)
				}
				calls = append(calls, strings.Join(args[4:], " "))
				if !failed && args[4] == failure {
					failed = true
					return "", cause
				}
				switch args[4] {
				case "findmnt":
					if !reflect.DeepEqual(args[4:], []string{"findmnt", "-rn", "-o", "TARGET,FSTYPE"}) {
						t.Fatal(args)
					}
					out := "invalid\n/foreign ext4\n" + paths[0] + " autofs\n" + paths[1] + " autofs\n"
					for i, active := range mounted {
						if active {
							out += paths[i] + " ext4\n"
						}
					}
					return out, nil
				case "umount":
					if len(args) != 7 || args[5] != "--" {
						t.Fatal(args)
					}
					for i, path := range paths {
						if args[6] == path && mounted[i] {
							mounted[i] = false
							if i == 0 {
								mounted[1] = true
							}
							return "", nil
						}
					}
					t.Fatalf("unexpected unmount: %v", args)
				}
				t.Fatalf("unexpected command: %v", args)
				return "", nil
			}
			if failure != "" {
				if err := UnmountOwnedVolumes(context.Background(), dir, run); !errors.Is(err, cause) || !strings.Contains(err.Error(), volumes[0].UUID) {
					t.Fatalf("error = %v", err)
				}
				want := 1
				if failure == "umount" {
					want = 2
				}
				if len(calls) != want || !mounted[0] || mounted[1] {
					t.Fatalf("continued after failure: %v %v", calls, mounted)
				}
			}
			calls = nil
			if err := UnmountOwnedVolumes(context.Background(), dir, run); err != nil {
				t.Fatal(err)
			}
			want := []string{"findmnt -rn -o TARGET,FSTYPE", "umount -- " + paths[0], "findmnt -rn -o TARGET,FSTYPE", "umount -- " + paths[1]}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %v", calls)
			}
			calls = nil
			if err := UnmountOwnedVolumes(context.Background(), dir, run); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 2 {
				t.Fatalf("repeat = %v", calls)
			}
		})
	}
}

func TestUnmountRegistryFailure(t *testing.T) {
	dir := writeUnmountVolumes(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "samba", "volumes.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context, string, ...string) (string, error) {
		t.Fatal("command after registry error")
		return "", nil
	}
	if err := UnmountOwnedVolumes(context.Background(), dir, run); err == nil {
		t.Fatal("accepted invalid registry")
	}
	if err := os.Remove(filepath.Join(dir, "samba", "volumes.json")); err != nil {
		t.Fatal(err)
	}
	if err := UnmountOwnedVolumes(context.Background(), dir, run); err != nil {
		t.Fatal(err)
	}
}

func TestUnmountTableShapes(t *testing.T) {
	v := config.StorageVolume{ID: "volume"}
	path := MountPath(v)
	for _, tc := range []struct {
		name, table string
		unmounts    int
	}{
		{"empty", "", 0},
		{"absent", "/foreign ext4\ninvalid\n" + path + " ext4 extra\n", 0},
		{"autofs", path + " autofs\n", 0},
		{"stacked", path + " autofs\n" + path + " ext4\n", 1},
		{"duplicate", path + " ext4\n" + path + " ext4\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unmounts := 0
			run := func(_ context.Context, _ string, args ...string) (string, error) {
				if args[4] == "findmnt" {
					return tc.table, nil
				}
				if !reflect.DeepEqual(args[4:], []string{"umount", "--", path}) {
					t.Fatal(args)
				}
				unmounts++
				return "", nil
			}
			if err := unmountVolume(context.Background(), run, v); err != nil {
				t.Fatal(err)
			}
			if unmounts != tc.unmounts {
				t.Fatalf("unmounts=%d, want %d", unmounts, tc.unmounts)
			}
		})
	}
}

func BenchmarkUnmountOwnedScan(b *testing.B) {
	for _, size := range [][2]int{{8, 128}, {128, 2048}} {
		b.Run(fmt.Sprintf("volumes%d_mounts%d", size[0], size[1]), func(b *testing.B) {
			volumes := make([]config.StorageVolume, size[0])
			for i := range volumes {
				volumes[i] = config.StorageVolume{ID: fmt.Sprintf("volume-%d", i)}
			}
			dir := writeUnmountVolumes(b, volumes)
			var prefix strings.Builder
			for i := 0; i < size[1]; i++ {
				fmt.Fprintf(&prefix, "/foreign/%d ext4\n", i)
			}
			snapshots := make([]string, len(volumes))
			for i := range volumes {
				snapshots[i] = prefix.String() + MountPath(volumes[i]) + " ext4\n"
			}
			queries, commands := 0, 0
			run := func(_ context.Context, _ string, args ...string) (string, error) {
				commands++
				if args[4] == "findmnt" {
					out := snapshots[queries]
					queries++
					return out, nil
				}
				return "", nil
			}
			b.ReportAllocs()
			for b.Loop() {
				queries, commands = 0, 0
				if err := UnmountOwnedVolumes(context.Background(), dir, run); err != nil {
					b.Fatal(err)
				}
				if queries != len(volumes) || commands != 2*len(volumes) {
					b.Fatal(queries, commands)
				}
			}
		})
	}
}
