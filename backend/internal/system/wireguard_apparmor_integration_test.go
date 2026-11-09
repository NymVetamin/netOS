//go:build linux

package system

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Профиль wg в режиме enforce на настоящей ОС: без блока netOS wg syncconf
// не читает конфигурацию из каталога состояния, с блоком — читает, после
// удаления блока — снова нет. Исходный режим профиля восстанавливается.
func TestIntegrationWireGuardAppArmor(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == host {
		t.Fatal("refusing host namespace")
	}
	const dir, profiles = "/etc/apparmor.d", "/sys/kernel/security/apparmor/profiles"
	if _, err := os.Stat(filepath.Join(dir, "wg")); err != nil {
		t.Skip("профиля AppArmor wg нет")
	}
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg unavailable")
	}
	loaded, err := os.ReadFile(profiles)
	if err != nil || !strings.Contains(string(loaded), "\nwg (") && !strings.HasPrefix(string(loaded), "wg (") {
		t.Skip("профиль wg не загружен")
	}
	ctx := context.Background()
	r := NewExec()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := r.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %s %v", name, args, out, err)
		}
		return strings.TrimSpace(out)
	}
	reload := []string{"-r", filepath.Join(dir, "wg")}
	if strings.Contains(string(loaded), "\nwg (complain)") || strings.HasPrefix(string(loaded), "wg (complain)") {
		reload = []string{"-r", "-C", filepath.Join(dir, "wg")}
	}
	t.Cleanup(func() {
		_ = RemoveWireGuardAppArmor(ctx, dir, profiles, r.Run)
		_, _ = r.Run(ctx, "apparmor_parser", reload...)
	})
	run("apparmor_parser", "-r", filepath.Join(dir, "wg"))

	stateDir, err := os.MkdirTemp("/var/lib", "netos-wg-armor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	conf := filepath.Join(stateDir, "wg-ch999.conf")
	if err := os.WriteFile(conf, []byte("[Interface]\nPrivateKey = "+run("wg", "genkey")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("ip", "link", "add", "wg-ch999", "type", "wireguard")
	t.Cleanup(func() { _, _ = r.Run(ctx, "ip", "link", "del", "wg-ch999") })

	if out, err := r.Run(ctx, "wg", "syncconf", "wg-ch999", conf); err == nil {
		t.Fatalf("enforce не действует: wg прочитал %s без разрешения: %s", conf, out)
	}
	if err := EnsureWireGuardAppArmor(ctx, dir, profiles, stateDir, r.Run); err != nil {
		t.Fatal(err)
	}
	run("wg", "syncconf", "wg-ch999", conf)
	if err := RemoveWireGuardAppArmor(ctx, dir, profiles, r.Run); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(ctx, "wg", "syncconf", "wg-ch999", conf); err == nil {
		t.Fatal("после удаления блока разрешение осталось")
	}
}
