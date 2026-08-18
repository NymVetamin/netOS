//go:build linux

package services

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDHCPProviderSyntax(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("задайте NETOS_INTEGRATION=1")
	}
	if os.Geteuid() != 0 {
		t.Skip("интеграционная проверка DHCP требует root")
	}
	cfg := providerTestConfig()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			cfg.Interfaces[0].Name = iface.Name
			break
		}
	}
	dir := t.TempDir()

	if binary, err := exec.LookPath("dhcpd"); err == nil {
		conf := filepath.Join(dir, "dhcpd.conf")
		leases := filepath.Join(dir, "dhcpd.leases")
		if err := os.WriteFile(conf, []byte(NewISCDHCP(nil).Render(cfg)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(leases, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(binary, "-4", "-t", "-cf", conf, "-lf", leases).CombinedOutput(); err != nil {
			t.Fatalf("dhcpd отклонил конфиг: %v\n%s", err, out)
		}
	} else {
		t.Log("dhcpd не установлен")
	}

	if binary, err := exec.LookPath("kea-dhcp4"); err == nil {
		conf := filepath.Join(dir, "kea.json")
		if err := os.WriteFile(conf, []byte(NewKeaDHCP(nil).Render(cfg)), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(binary, "-t", conf).CombinedOutput(); err != nil {
			t.Fatalf("Kea отклонил конфиг: %v\n%s", err, out)
		}
	} else {
		t.Log("kea-dhcp4 не установлен")
	}
}
