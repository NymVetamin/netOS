package samba

import (
	"context"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUUIDCaseApplyHealthRepairAndRetry(t *testing.T) {
	r := newRunner()
	s := testSubsystem(t, r)
	c := fixture()
	ctx := context.Background()
	c.Samba.Volumes[0].UUID = "abcd-1234"
	r.devices = `{"blockdevices":[{"path":"/dev/test","uuid":"ABCD-1234","fstype":"exfat","type":"part"}]}`
	for i := 0; i < 2; i++ {
		if err := s.Apply(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	v := c.Samba.Volumes[0]
	path := filepath.Join(s.UnitDir, mountUnit(v))
	correct := mountText(v, "991", "993")
	if err := os.WriteFile(path, []byte(strings.Replace(correct, "ABCD-1234", "abcd-1234", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	if s.Health(ctx, c) == nil {
		t.Fatal("old noncanonical unit accepted")
	}
	r.fail = "systemctl daemon-reload"
	if s.Apply(ctx, c) == nil {
		t.Fatal("reload failure ignored")
	}
	r.fail = ""
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != correct {
		t.Fatalf("repair: %v", err)
	}
	if c.Samba.Volumes[0].UUID != "abcd-1234" {
		t.Fatal("saved UUID mutated")
	}
}
func TestMountUUIDCanonicalCase(t *testing.T) {
	for _, tc := range []struct{ fs, entered, actual string }{
		{"vfat", "abcd-1234", "ABCD-1234"}, {"exfat", "abcd-1234", "ABCD-1234"}, {"ntfs", "abcd1234abcd5678", "ABCD1234ABCD5678"},
		{"ext2", "ABCDEF12-3456-7890-ABCD-123456789ABC", "abcdef12-3456-7890-abcd-123456789abc"},
		{"ext3", "ABCDEF12-3456-7890-ABCD-123456789ABC", "abcdef12-3456-7890-abcd-123456789abc"},
		{"ext4", "ABCDEF12-3456-7890-ABCD-123456789ABC", "abcdef12-3456-7890-abcd-123456789abc"},
		{"exfat", "AbCd-1234", "ABCD-1234"},
		{"vfat", "1234-5678", "1234-5678"},
		{"unknown", "AbCd-1234", "AbCd-1234"},
	} {
		t.Run(tc.fs, func(t *testing.T) {
			v := config.StorageVolume{ID: "auditcase", UUID: tc.entered, Filesystem: tc.fs, Enabled: true}
			if err := checkVolumeDevices([]config.StorageVolume{v}, []Device{{UUID: tc.actual, Filesystem: tc.fs, Available: true}}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(mountText(v, "0", "0"), "What=/dev/disk/by-uuid/"+tc.actual+"\n") {
				t.Fatal("preflight accepts UUID but mount unit uses noncanonical path")
			}
			first := mountText(v, "0", "0")
			v.UUID = tc.actual
			if mountText(v, "0", "0") != first {
				t.Fatal("canonical input changes unit")
			}
		})
	}
}
