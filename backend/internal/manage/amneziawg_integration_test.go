//go:build linux

package manage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/amneziawg"
	"github.com/netos-router/netos/internal/system"
)

func TestAmneziaWGCleanupProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			if err := amneziawg.Execute(context.Background(), os.Args[i+1:], os.Stdout); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Skip("child helper")
}

func TestIntegrationAmneziaWGCleanup(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		host, _ := os.Readlink("/proc/1/ns/" + kind)
		if self == host {
			t.Fatal("refusing host namespace")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	root, err := os.MkdirTemp("/var/lib", "netos-awg-cleanup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	m := New("test")
	m.Root = root
	m.StateDir = filepath.Join(root, "var/lib/netos")
	binary := filepath.Join(root, "runner")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	dir := m.sys("/etc/systemd/system")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, iface := range []string{"awg-ch993", "awg-srv993"} {
		unit := system.AmneziaWGUnitName(iface)
		link := filepath.Join("/etc/systemd/system", unit)
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Fatal("test unit already exists")
		}
		for _, path := range []string{filepath.Join("/sys/class/net", iface), filepath.Join(amneziawg.SocketDir, iface+".sock")} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("test interface or socket already exists")
			}
		}
		path := filepath.Join(dir, unit)
		body := fmt.Sprintf("[Service]\nType=notify\nNetworkNamespacePath=/proc/%d/ns/net\nExecStart=%s -test.run=TestAmneziaWGCleanupProcess -- serve %s\n", os.Getpid(), binary, iface)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			exec.Command("systemctl", "stop", unit).Run()
			os.Remove(link)
			exec.Command("systemctl", "daemon-reload").Run()
			exec.Command("systemctl", "reset-failed", unit).Run()
		}()
		run("systemctl", "link", path)
		run("systemctl", "start", unit)
		if _, err := os.Stat(filepath.Join("/sys/class/net", iface)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(amneziawg.SocketDir, iface+".sock")); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := m.removeComponentUnits(ctx); err != nil {
			t.Fatal(err)
		}
		for _, iface := range []string{"awg-ch993", "awg-srv993"} {
			unit := system.AmneziaWGUnitName(iface)
			out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).CombinedOutput()
			if strings.TrimSpace(string(out)) == "active" {
				t.Fatal("cleanup left daemon active")
			}
			for _, path := range []string{filepath.Join(dir, unit), filepath.Join("/etc/systemd/system", unit), filepath.Join("/sys/class/net", iface), filepath.Join(amneziawg.SocketDir, iface+".sock")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("cleanup retained %s: %v", path, err)
				}
			}
		}
	}
}
