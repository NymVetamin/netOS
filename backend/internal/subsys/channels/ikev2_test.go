package channels

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRemoveOwnedIKEv2Unit(t *testing.T) {
	ch := config.Channel{Type: "ikev2", Index: 3}
	unit := ikev2UnitName(ch)
	for _, tc := range []struct {
		name, recorded, failOnce string
		wantPairs                int
	}{
		{"recorded", unit, "", 1},
		{"without recorded unit", "", "", 1},
		{"legacy unit", "legacy-ike.service", "", 1},
		{"retry stop", unit, "systemctl stop " + unit, 2},
		{"retry disable", unit, "systemctl disable " + unit, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r := newTestSubsystem(t)
			r.failOnce = tc.failOnce
			if err := s.writeOwned([]ownedChannel{{Name: InterfaceName(ch), Index: ch.Index, Type: ch.Type, Unit: tc.recorded}}); err != nil {
				t.Fatal(err)
			}
			p := s.ikev2Paths(ch)
			for _, file := range []string{p.conf, p.unit} {
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			apply := func() {
				t.Helper()
				if err := s.Apply(context.Background(), &config.Config{}); err != nil {
					t.Fatal(err)
				}
			}
			apply()
			counts := make(map[string]int)
			for _, cmd := range r.commands {
				counts[cmd]++
			}
			for _, verb := range []string{"disable", "stop"} {
				cmd := "systemctl " + verb + " "
				if counts[cmd+unit] != tc.wantPairs {
					t.Errorf("%s%s: got %d, want %d", cmd, unit, counts[cmd+unit], tc.wantPairs)
				}
				if tc.recorded != "" && tc.recorded != unit && counts[cmd+tc.recorded] != 1 {
					t.Errorf("missing cleanup of %s", tc.recorded)
				}
			}
			for _, file := range []string{p.unit, p.root} {
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatalf("%s remains: %v", file, err)
				}
			}
			r.commands = nil
			apply()
			for _, cmd := range r.commands {
				if strings.Contains(cmd, unit) {
					t.Fatalf("repeated removal: %s", cmd)
				}
			}
		})
	}
}

func TestIKEv2ClientRendersIsolatedXFRMAndEAP(t *testing.T) {
	ch := config.Channel{Index: 3, Name: "office", Type: "ikev2"}
	ike := config.IKEv2ChannelConfig{Server: "vpn.example.com", ServerIdentity: "vpn.example.com", Username: "alice", Password: "secret-password"}
	conf := string(renderIKEv2Client(ch, ike))
	for _, want := range []string{"remote_addrs = vpn.example.com", "auth = eap-mschapv2", "if_id_in = 60003", "if_id_out = 60003", "vips = 0.0.0.0"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in client config", want)
		}
	}
	if strings.Contains(conf, ike.Password) {
		t.Fatal("plaintext EAP password in strongSwan config")
	}
	daemon := string(renderIKEv2ClientDaemon(ch))
	if !strings.Contains(daemon, "port = 0") || !strings.Contains(daemon, "install_virtual_ip_on = xfrm-ch3") || !strings.Contains(daemon, "install_routes = no") {
		t.Fatal("daemon isolation or route ownership missing")
	}
	if !strings.Contains(string(renderIKEv2ClientUnit(ch, ikev2ClientPaths{})), "--initiate --child netos-ch3") {
		t.Fatal("client unit does not initiate connection")
	}
}

func TestIKEv2DNSHandlerLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the strongSwan DNS hook runs on Linux")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "resolv.conf")
	ch := config.Channel{Index: 45, Type: "ikev2"}
	script := strings.ReplaceAll(string(renderIKEv2DNSUpdate(ch)), "/run/"+ikev2RuntimeName(ch)+"/resolv.conf", target)
	path := filepath.Join(dir, "dns-update")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(input string, args ...string) error {
		cmd := exec.Command("/bin/sh", append([]string{path}, args...)...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.Run()
	}
	for cycle := 0; cycle < 2; cycle++ {
		want := "nameserver 198.18.0.1\nnameserver 2001:db8::53\n"
		if err := run(want, "-a", "xfrm-ch45"); err != nil {
			t.Fatal(err)
		}
		if err := run("", "-d", "xfrm-ch46"); err == nil {
			t.Fatal("another channel was allowed to delete learned DNS")
		}
		data, err := os.ReadFile(target)
		if err != nil || string(data) != want {
			t.Fatalf("DNS data lost or overwritten: %q, %v", data, err)
		}
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0600 {
			t.Fatal("learned DNS is not private")
		}
		if err := run("", "-d", "xfrm-ch45"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatal("stale DNS survived channel disconnect")
		}
	}
}

func TestIKEv2PushDNSUsesChannelInterface(t *testing.T) {
	for _, index := range []int{3, 45} {
		ch := config.Channel{Index: index, Type: "ikev2"}
		daemon := string(renderIKEv2ClientDaemon(ch))
		if !strings.Contains(daemon, "iface = "+InterfaceName(ch)) || strings.Contains(daemon, "iface = lo") {
			t.Fatalf("DNS push does not target the isolated channel: %s", daemon)
		}
		if !strings.Contains(daemon, "path = /bin/sh /run/"+ikev2RuntimeName(ch)+"/dns-update") {
			t.Fatal("DNS attribute handler still depends on the host resolvconf")
		}
		helper := string(renderIKEv2DNSUpdate(ch))
		if !strings.Contains(helper, "test \"$2\" = '"+InterfaceName(ch)+"'") ||
			!strings.Contains(helper, "target='/run/"+ikev2RuntimeName(ch)+"/resolv.conf'") ||
			strings.Contains(helper, "/etc/resolv.conf") || strings.Contains(helper, "resolvectl") {
			t.Fatal("learned DNS may overwrite another channel or the panel's resolver")
		}
		unit := string(renderIKEv2ClientUnit(ch, ikev2ClientPaths{root: "/owned/channel"}))
		if !strings.Contains(unit, "ExecStartPre=/usr/bin/install -m 0700 "+filepath.Join("/owned/channel", "dns-update")+" /run/"+ikev2RuntimeName(ch)+"/dns-update") {
			t.Fatal("DNS handler not installed in the writable unit runtime directory")
		}
	}
}
