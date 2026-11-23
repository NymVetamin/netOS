//go:build linux

package samba

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestIntegrationVolumeUUIDCase(t *testing.T) {
	if os.Getenv("NETOS_STORAGE_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_STORAGE_INTEGRATION=1 and root required")
	}
	for _, fs := range []string{"ext2", "ext3", "ext4", "vfat", "exfat", "ntfs"} {
		t.Run(fs, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			run := func(name string, args ...string) string {
				t.Helper()
				out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %s: %v", name, args, out, err)
				}
				return strings.TrimSpace(string(out))
			}
			root := t.TempDir()
			image := filepath.Join(root, "volume.img")
			file, err := os.Create(image)
			if err != nil {
				t.Fatal(err)
			}
			err = file.Truncate(128 << 20)
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("image: %v %v", err, closeErr)
			}
			args := []string{image}
			switch fs {
			case "ext2", "ext3", "ext4":
				args = []string{"-F", image}
			case "vfat":
				args = []string{"-i", "ABCD1234", image}
			case "ntfs":
				args = []string{"-F", "-Q", image}
			}
			var uuid string
			for attempt := 0; attempt < 16; attempt++ {
				run("mkfs."+fs, args...)
				uuid = run("blkid", "-p", "-s", "UUID", "-o", "value", image)
				if strings.ToLower(uuid) != strings.ToUpper(uuid) {
					break
				}
			}
			if strings.ToLower(uuid) == strings.ToUpper(uuid) {
				t.Fatal("formatter produced no letter to exercise UUID case")
			}
			loop := run("losetup", "--find", "--show", image)
			t.Cleanup(func() {
				if out, err := exec.Command("losetup", "--detach", loop).CombinedOutput(); err != nil {
					t.Errorf("detach: %s %v", out, err)
				}
			})
			run("udevadm", "trigger", "--action=change", loop)
			run("udevadm", "settle", "--timeout=10")
			actual := filepath.Join("/dev/disk/by-uuid", uuid)
			resolved, err := filepath.EvalSymlinks(actual)
			if err != nil || resolved != loop {
				t.Fatalf("udev path %s: %s %v", actual, resolved, err)
			}
			entered := strings.ToLower(uuid)
			if entered == uuid {
				entered = strings.ToUpper(uuid)
			}
			if _, err := os.Stat(filepath.Join("/dev/disk/by-uuid", entered)); !os.IsNotExist(err) {
				t.Fatalf("opposite-case path unexpectedly exists: %v", err)
			}
			v := config.StorageVolume{ID: root, UUID: entered, Filesystem: fs, Enabled: true}
			if err := checkVolumeDevices([]config.StorageVolume{v}, []Device{{UUID: uuid, Filesystem: fs, Available: true}}); err != nil {
				t.Fatal(err)
			}
			mount := MountPath(v)
			if err := os.MkdirAll(filepath.Dir(mount), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(mount, 0755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Remove(mount); err != nil {
					t.Errorf("mount directory cleanup: %v", err)
				}
			})
			unit := mountUnit(v)
			unitPath := filepath.Join("/run/systemd/system", unit)
			f, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if out, err := exec.Command("systemctl", "stop", unit).CombinedOutput(); err != nil {
					t.Errorf("stop: %s %v", out, err)
				}
				if err := os.Remove(unitPath); err != nil {
					t.Errorf("unit cleanup: %v", err)
				}
				_ = exec.Command("systemctl", "daemon-reload").Run()
				_ = exec.Command("systemctl", "reset-failed", unit).Run()
			})
			correct := mountText(v, "0", "0")
			legacy := strings.Replace(correct, "What=/dev/disk/by-uuid/"+uuid+"\n", "What=/dev/disk/by-uuid/"+entered+"\n", 1)
			_, writeErr := f.WriteString(legacy)
			closeErr = f.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("unit: %v %v", writeErr, closeErr)
			}
			run("systemctl", "daemon-reload")
			if out, err := exec.CommandContext(ctx, "systemctl", "start", unit).CombinedOutput(); err == nil {
				t.Fatalf("legacy opposite-case UUID unexpectedly mounted: %s", out)
			}
			if err := os.WriteFile(unitPath, []byte(correct), 0644); err != nil {
				t.Fatal(err)
			}
			run("systemctl", "daemon-reload")
			run("systemctl", "reset-failed", unit)
			for repeat := 0; repeat < 2; repeat++ {
				run("systemctl", "start", unit)
				got := run("findmnt", "-rn", "-M", mount, "-o", "UUID")
				if got != uuid {
					t.Fatalf("mounted wrong volume: %q expected %q", got, uuid)
				}
				run("systemctl", "stop", unit)
			}
			t.Logf("%s: opposite-case path absent; generated unit mounted UUID %s twice", fs, uuid)
		})
	}
}
