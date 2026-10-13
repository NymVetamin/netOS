package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestUninstallSSHProtectionLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		failDHCP, failProtect bool
	}{
		{name: "success"}, {name: "DHCP failure", failDHCP: true}, {name: "protection failure", failProtect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			if err := os.MkdirAll(m.sys("/sys/class/net/eth0/device"), 0700); err != nil {
				t.Fatal(err)
			}
			m.Getenv = func(key string) string {
				if key == "SSH_CONNECTION" {
					return "198.51.100.9 4567 192.0.2.10 22"
				}
				return ""
			}
			protected, stopped, dhcp, removed := false, false, false, false
			m.Output = func(_ context.Context, name string, args ...string) (string, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ip -4 route show default":
					if !stopped {
						return "default via 192.0.2.1 dev eth0 proto 201 metric 100", nil
					}
					if dhcp {
						return "default via 192.0.2.1 dev eth0 proto dhcp", nil
					}
					return "default dev eth0 src 169.254.1.2 metric 1001009", nil
				case "ip -o -4 addr show dev eth0":
					return "2: eth0 inet 192.0.2.10/24 scope global eth0", nil
				case "ip -j -4 route show table main exact 198.51.100.9/32":
					return "[]", nil
				case "ifquery --list":
					return "lo\neth0\n", nil
				}
				return "", nil
			}
			m.Run = func(_ context.Context, c command) error {
				cmd := c.name + " " + strings.Join(c.args, " ")
				switch cmd {
				case "ip -4 route add 198.51.100.9/32 via 192.0.2.1 dev eth0 proto boot metric 42760":
					if stopped {
						t.Fatal("protected after stopping daemon")
					}
					if tc.failProtect {
						return errors.New("route rejected")
					}
					protected = true
				case "systemctl stop netosd":
					if !protected {
						t.Fatal("SSH unprotected before stop")
					}
					stopped = true
				case "ip -4 route flush table all proto 201":
					if !protected {
						t.Fatal("SSH unprotected during flush")
					}
				case "ifup -a --allow=hotplug":
					dhcp = !tc.failDHCP
				case "ip -4 route del 198.51.100.9/32 via 192.0.2.1 dev eth0 proto boot metric 42760":
					if !dhcp {
						t.Fatal("protection removed before DHCP restored")
					}
					protected = false
					removed = true
				}
				return nil
			}
			err := m.uninstall(context.Background(), true, false, false, true)
			if (err != nil) != (tc.failDHCP || tc.failProtect) {
				t.Fatalf("err=%v", err)
			}
			if tc.failProtect && stopped {
				t.Fatal("changed services after failed protection")
			}
			if tc.failDHCP && (!protected || removed || strings.Contains(out.String(), "netOS удалён.")) {
				t.Fatal("lost recovery or false success")
			}
			if !tc.failProtect && !tc.failDHCP && (!removed || protected) {
				t.Fatal("temporary route left behind")
			}
		})
	}
}

func TestUninstallSSHProtectionRetryAndForeignRoute(t *testing.T) {
	for _, local := range []bool{false, true} {
		m, _ := testManager()
		sandbox(t, m)
		peer := "198.51.100.9"
		if local {
			peer = "192.0.2.9"
		}
		m.Getenv = func(string) string { return peer + " 4567 192.0.2.10 22" }
		uplink := managementUplink{device: "eth0", address: "192.0.2.10/24", route: []string{"-4", "route", "replace", "default", "via", "192.0.2.1", "dev", "eth0"}}
		// Real iproute2 JSON omits protocol boot as well as the /32 suffix.
		route := uninstallSSHRoute{Destination: peer, Device: "eth0", Metric: 42760}
		if !local {
			route.Gateway = "192.0.2.1"
		}
		exists := false
		adds, dels := 0, 0
		m.Output = func(context.Context, string, ...string) (string, error) {
			if !exists {
				return "[]", nil
			}
			b, _ := json.Marshal([]uninstallSSHRoute{route})
			return string(b), nil
		}
		m.Run = func(_ context.Context, c command) error {
			cmd := strings.Join(c.args, " ")
			if local && strings.Contains(cmd, " via ") {
				t.Fatal("local peer routed through gateway")
			}
			if c.args[2] == "add" {
				adds++
				exists = true
			} else if c.args[2] == "del" {
				dels++
				exists = false
			}
			return nil
		}
		if _, err := m.protectUninstallSSH(context.Background(), uplink); err != nil {
			t.Fatal(err)
		}
		// A failed operation retained its route and ownership. Retry reuses it.
		release, err := m.protectUninstallSSH(context.Background(), uplink)
		if err != nil {
			t.Fatal(err)
		}
		if adds != 1 {
			t.Fatal("retry replaced existing route")
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if dels != 1 || exists {
			t.Fatal("owned route not removed")
		}
		exists = true // Same route without our ownership record belongs to someone else.
		if _, err := m.protectUninstallSSH(context.Background(), uplink); err == nil {
			t.Fatal("adopted foreign route")
		}
		if adds != 1 || dels != 1 {
			t.Fatal("modified foreign route")
		}
	}
}

func TestUninstallSSHRetryFromConsoleOrDifferentPeer(t *testing.T) {
	for _, console := range []bool{false, true} {
		m, _ := testManager()
		sandbox(t, m)
		peer := "198.51.100.9"
		m.Getenv = func(string) string {
			if peer == "" {
				return ""
			}
			return peer + " 4567 192.0.2.10 22"
		}
		uplink := managementUplink{device: "eth0", address: "192.0.2.10/24", route: []string{"via", "192.0.2.1"}}
		live := map[string]uninstallSSHRoute{}
		m.Output = func(_ context.Context, _ string, args ...string) (string, error) {
			routes := []uninstallSSHRoute{}
			if r, ok := live[args[len(args)-1]]; ok {
				routes = append(routes, r)
			}
			b, _ := json.Marshal(routes)
			return string(b), nil
		}
		m.Run = func(_ context.Context, c command) error {
			dst := c.args[3]
			if c.args[2] == "add" {
				live[dst] = uninstallSSHRoute{Destination: dst, Gateway: "192.0.2.1", Device: "eth0", Metric: 42760}
			} else {
				delete(live, dst)
			}
			return nil
		}
		if _, err := m.protectUninstallSSH(context.Background(), uplink); err != nil {
			t.Fatal(err)
		}
		if console {
			peer = ""
		} else {
			peer = "198.51.100.11"
		}
		release, err := m.protectUninstallSSH(context.Background(), uplink)
		if err != nil {
			t.Fatal(err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if len(live) != 0 {
			t.Fatalf("leftover routes: %+v", live)
		}
	}
}
