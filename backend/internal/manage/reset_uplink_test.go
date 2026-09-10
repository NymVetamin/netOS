package manage

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetRetainsPhysicalUplinkForFactoryDetection(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.sys("/sys/class/net/eth0/device"), 0700); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(m.StateDir, "generated")
	if err := os.MkdirAll(generated, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-wan-addresses.json"), []byte(`[{"interface":"eth0","address":"192.0.2.10/24"},{"interface":"eth1","address":"198.18.0.2/24"},{"interface":"eth0","address":"192.0.2.11/24"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "ip -4 route show default":
			return "default via 192.0.2.1 dev eth0 proto 201 metric 100 onlink\n", nil
		case "ip -o -4 addr show dev eth0":
			return "2: eth0 inet 192.0.2.10/24 scope global eth0\n", nil
		}
		return "", nil
	}
	addressPresent, defaultPresent, routeProtected := true, true, false
	deleted := map[string]bool{}
	started := false
	m.Run = func(_ context.Context, c command) error {
		cmd := c.name + " " + strings.Join(c.args, " ")
		switch cmd {
		case "ip -4 route replace default via 192.0.2.1 dev eth0 proto boot metric 100 onlink":
			routeProtected = true
		case "ip -4 route flush table all proto 201":
			defaultPresent = routeProtected
		case "ip -4 addr del 192.0.2.10/24 dev eth0":
			addressPresent = false
		case "systemctl enable --now netosd":
			started = true
			if !addressPresent || !defaultPresent {
				t.Error("factory detection lost the management uplink")
			}
		}
		if strings.HasPrefix(cmd, "ip -4 addr del ") {
			deleted[cmd] = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reset", "-y", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	if !started || !deleted["ip -4 addr del 198.18.0.2/24 dev eth1"] || !deleted["ip -4 addr del 192.0.2.11/24 dev eth0"] {
		t.Fatalf("incomplete reset: started=%v deleted=%v", started, deleted)
	}
}

func TestResetUplinkInspectionFailureDoesNotStopDaemon(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) { return "", errors.New("route query failed") }
	m.Run = func(context.Context, command) error { t.Fatal("mutated machine after failed inspection"); return nil }
	if err := m.Execute(context.Background(), []string{"reset", "-y", "--no-backup"}); err == nil {
		t.Fatal("inspection error ignored")
	}
}

func TestRestoreRetainsPhysicalManagementUplinkUntilDaemonIsReady(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.sys("/sys/class/net/eth0/device"), 0700); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(m.StateDir, "generated")
	if err := os.MkdirAll(generated, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-wan-addresses.json"), []byte(`[{"interface":"eth0","address":"192.0.2.10/24"},{"interface":"eth1","address":"198.18.0.2/24"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.BackupDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(m.BackupDir, "netos-backup-20260101-000000.tar.gz")
	data, err := os.ReadFile(writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, data, 0600); err != nil {
		t.Fatal(err)
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "ip -4 route show default":
			return "default via 192.0.2.1 dev eth0 proto 201 metric 100 onlink\n", nil
		case "ip -o -4 addr show dev eth0":
			return "2: eth0 inet 192.0.2.10/24 scope global eth0\n", nil
		case "systemctl is-active netosd":
			return "active\n", nil
		}
		return "", nil
	}
	addressPresent, defaultPresent, routeProtected := true, true, false
	removedOther := false
	m.Run = func(_ context.Context, c command) error {
		cmd := c.name + " " + strings.Join(c.args, " ")
		switch cmd {
		case "ip -4 route replace default via 192.0.2.1 dev eth0 proto boot metric 100 onlink":
			routeProtected = true
		case "ip -4 route flush table all proto 201":
			defaultPresent = routeProtected
		case "ip -4 addr del 192.0.2.10/24 dev eth0":
			addressPresent = false
		case "ip -4 addr del 198.18.0.2/24 dev eth1":
			removedOther = true
		case "systemctl start netosd":
			if !addressPresent || !defaultPresent {
				t.Error("restore lost the management uplink before netosd became ready")
			}
			if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0644)
		}
		if c.name == "tar" && contains(c.args, "-czf") {
			for i, arg := range c.args {
				if arg == "-czf" && i+1 < len(c.args) {
					return os.WriteFile(c.args[i+1], []byte("mock archive"), 0600)
				}
			}
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"restore", backup, "--yes"}); err != nil {
		t.Fatal(err)
	}
	if !removedOther {
		t.Fatal("restore did not remove a non-management owned address")
	}
}
