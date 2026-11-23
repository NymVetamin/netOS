package samba

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type ownershipRunner struct {
	*fakeRunner
	onReload func()
}

func (r *ownershipRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" && r.onReload != nil {
		r.onReload()
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestVolumeOwnershipSurvivesPartialApplyAndRepeat(t *testing.T) {
	r := &ownershipRunner{fakeRunner: newRunner()}
	s := New(r, filepath.Join(t.TempDir(), "state"))
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	c := fixture()
	c.Samba.Enabled = false
	want, _ := json.Marshal(c.Samba.Volumes)
	path := filepath.Join(s.StateDir, "samba", "volumes.json")
	check := func() {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("ownership=%s err=%v", got, err)
		}
	}
	r.onReload = check
	r.fail = "daemon-reload"
	if err := s.Apply(context.Background(), c); err == nil {
		t.Fatal("reload failure hidden")
	}
	check()
	r.fail = ""
	r.onReload = func() {
		check()
		if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := s.Apply(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		check() // The later write must still check and restore the owned snapshot.
	}
}

func BenchmarkApplyVolumeSnapshot(b *testing.B) {
	for _, n := range []int{8, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := newRunner()
			s := New(r, filepath.Join(b.TempDir(), "state"))
			s.UnitDir = filepath.Join(b.TempDir(), "units")
			c := config.Default()
			for i := 0; i < n; i++ {
				c.Samba.Volumes = append(c.Samba.Volumes, config.StorageVolume{ID: fmt.Sprintf("v%d", i), UUID: fmt.Sprintf("%08x", i), Filesystem: "ext4", Enabled: true})
			}
			ctx := context.Background()
			if err := s.Apply(ctx, c); err != nil {
				b.Fatal(err)
			}
			commands := 0
			b.ReportAllocs()
			for b.Loop() {
				r.calls = nil
				if err := s.Apply(ctx, c); err != nil {
					b.Fatal(err)
				}
				commands += len(r.calls)
			}
			b.ReportMetric(float64(commands)/float64(b.N), "commands/op")
		})
	}
}
