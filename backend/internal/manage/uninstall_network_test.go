package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallRestoresDHCPAfterNetworkdAndKeepsRecoveryOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name           string
		recorded, fail bool
	}{
		{"old baseline", false, false}, {"new baseline", true, false},
		{"DHCP failure", true, true}, {"DHCP returned no route", true, true}, {"old baseline DHCP failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			baseline := systemBaseline{Version: 1, Sysctl: map[string]string{}, DefaultRoutes4: []string{"default via 192.0.2.1 dev eth0 proto dhcp"}}
			if tc.recorded {
				baseline.NetworkServices = map[string]serviceBaseline{
					"networking.service":       {Enabled: "enabled", Active: "active"},
					"systemd-networkd.service": {Enabled: "disabled", Active: "inactive"},
					"systemd-networkd.socket":  {Enabled: "disabled", Active: "inactive"},
				}
			}
			data, _ := json.Marshal(baseline)
			baselinePath := m.sys(systemBaselineDir + "/state.json")
			generated := m.sys("/etc/systemd/network/05-netos-eth0.network")
			marker := filepath.Join(m.StateDir, "database-marker")
			for path, body := range map[string][]byte{baselinePath: data, generated: []byte("netos config"), marker: []byte("keep"), m.Binary: []byte("binary"), m.CLI: []byte("cli"), m.Unit: []byte("unit"), m.sys("/etc/network/interfaces"): []byte("allow-hotplug eth0\niface eth0 inet dhcp\n")} {
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			route, dhcp, emergency := true, false, false
			var commands []string
			m.Output = func(_ context.Context, name string, args ...string) (string, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ip -4 route show default":
					if route {
						return "default via 192.0.2.1 dev eth0 proto dhcp\n", nil
					}
				case "ifquery --list":
					return "lo\neth0\n", nil
				}
				if strings.Contains(cmd, "--property=LoadState") {
					return "loaded\n", nil
				}
				return "", nil
			}
			m.Run = func(_ context.Context, c command) error {
				cmd := c.name + " " + strings.Join(c.args, " ")
				commands = append(commands, cmd)
				if cmd == "ip -4 route flush table all proto 201" {
					route = false
				}
				if cmd == "ifup -a --allow=hotplug" {
					if _, err := os.Stat(generated); !os.IsNotExist(err) {
						t.Fatal("DHCP started before releasing netOS config")
					}
					if tc.fail {
						if tc.name == "DHCP returned no route" {
							return nil
						}
						return errors.New("DHCP unavailable")
					}
					dhcp = true
					route = true
				}
				if cmd == "ip -4 route add default via 192.0.2.1 dev eth0" {
					emergency = true
					route = true
				}
				return nil
			}
			err := m.uninstall(context.Background(), true, false, false, true)
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v", err)
			}
			if tc.fail {
				if !emergency || !route || strings.Contains(out.String(), "netOS удалён.") {
					t.Fatal("failed restore reported success or lost emergency route")
				}
				for _, path := range []string{marker, m.Binary, m.CLI, m.Unit, baselinePath} {
					if _, err := os.Stat(path); err != nil {
						t.Fatalf("recovery artifact lost: %s", path)
					}
				}
			} else {
				if !dhcp || !route || emergency {
					t.Fatal("DHCP did not restore connectivity")
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("successful uninstall kept database")
				}
			}
			joined := strings.Join(commands, "\n")
			if !strings.Contains(joined, "systemctl enable networking.service") || !strings.Contains(joined, "systemctl start networking.service") {
				t.Fatal("ifupdown not enabled and started")
			}
			if tc.recorded && strings.Index(joined, "systemctl stop systemd-networkd.service") > strings.Index(joined, "systemctl start networking.service") {
				t.Fatal("network owners overlap")
			}
			log, err := os.ReadFile(m.sys(uninstallLogPath))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "ifup -a --allow=hotplug") || !strings.Contains(string(log), "Завершение удаления") {
				t.Fatal("uninstall transcript incomplete")
			}
		})
	}
}

func TestRestoreNetworkdUnmasksBeforeStartingAndDoesNotStartIfupdown(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	baseline := &systemBaseline{NetworkServices: map[string]serviceBaseline{
		"networking.service":       {Enabled: "disabled", Active: "inactive"},
		"systemd-networkd.service": {Enabled: "enabled", Active: "active"},
		"systemd-networkd.socket":  {Enabled: "enabled", Active: "active"},
	}}
	var commands []string
	m.Run = func(_ context.Context, c command) error {
		commands = append(commands, c.name+" "+strings.Join(c.args, " "))
		return nil
	}
	if _, err := m.restoreOriginalNetworkServices(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "ifup ") || strings.Contains(joined, "start networking.service") {
		t.Fatal("started unwanted ifupdown")
	}
	if strings.Index(joined, "unmask systemd-networkd.service") > strings.Index(joined, "start systemd-networkd.service") {
		t.Fatal("masked owner started")
	}
	if strings.Index(joined, "stop networking.service") > strings.Index(joined, "start systemd-networkd.socket") {
		t.Fatal("old owner still active")
	}
}

func TestUninstallLogFailureStopsBeforeMutations(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.sys(uninstallLogPath), 0755); err != nil {
		t.Fatal(err)
	}
	m.Run = func(context.Context, command) error { t.Fatal("changed machine without a transcript"); return nil }
	if err := m.uninstall(context.Background(), true, false, false, true); err == nil {
		t.Fatal("log failure ignored")
	}
}

func TestUninstallLogSurvivesClosedConsole(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	m.Out, m.Err = failingConsole{}, failingConsole{}
	finish, err := m.beginUninstallLog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Out.Write([]byte("after disconnect\n")); err != nil {
		t.Fatal(err)
	}
	finish(errors.New("test failure"))
	data, err := os.ReadFile(m.sys(uninstallLogPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "after disconnect") || !strings.Contains(string(data), "test failure") {
		t.Fatal("log lost after disconnect")
	}
}

type failingConsole struct{}

func (failingConsole) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }

func TestRestoreHotplugWithInactiveNetworking(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	baseline := &systemBaseline{
		NetworkServices: map[string]serviceBaseline{
			"networking.service": {Enabled: "disabled", Active: "inactive"},
		},
		IfupdownInterfaces: []string{"eth0"},
	}
	var commands []string
	m.Run = func(_ context.Context, c command) error {
		commands = append(commands, c.name+" "+strings.Join(c.args, " "))
		return nil
	}
	if _, err := m.restoreOriginalNetworkServices(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "ifup eth0") || strings.Contains(joined, "start networking.service") || strings.Contains(joined, "enable networking.service") {
		t.Fatalf("hotplug ownership not restored: %s", joined)
	}
}
