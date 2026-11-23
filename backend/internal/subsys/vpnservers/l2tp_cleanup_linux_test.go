package vpnservers

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIntegrationL2TPCleanupWriteFailure(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("explicit isolated root integration only")
	}
	for _, kind := range []string{"mnt", "net"} {
		self, e := os.Readlink("/proc/self/ns/" + kind)
		host, h := os.Readlink("/proc/1/ns/" + kind)
		if e != nil || h != nil || self == host {
			t.Fatal("refusing host namespace", kind)
		}
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	checkL2TPCleanupWriteFailure(t, func(path string) func() {
		// A mounted regular file remains readable but cannot be atomically replaced.
		if err := unix.Mount(path, path, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		unmounted := false
		unmount := func() {
			if !unmounted {
				if err := unix.Unmount(path, 0); err != nil {
					t.Fatal(err)
				}
				unmounted = true
			}
		}
		t.Cleanup(unmount)
		return unmount
	})
	t.Log("real rename failure preserved CHAP and ownership; unmount, retry and repeat PASS")
}
