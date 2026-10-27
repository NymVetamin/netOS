//go:build linux

package vpnservers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationL2TPChannelPreservesSession(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	for _, name := range []string{"xl2tpd", "pppd", "ip", "ping"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("missing %s", name)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := runner.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return strings.TrimSpace(out)
	}
	const ns = "netos-l2tp996"
	run("ip", "netns", "add", ns)
	t.Cleanup(func() {
		out, _ := runner.Run(ctx, "ip", "netns", "pids", ns)
		for _, pid := range strings.Fields(out) {
			_, _ = runner.Run(ctx, "kill", "-TERM", pid)
		}
		_, _ = runner.Run(ctx, "ip", "netns", "delete", ns)
	})
	run("ip", "link", "add", "veth-l2tp996h", "type", "veth", "peer", "name", "veth-l2tp996c")
	t.Cleanup(func() { _, _ = runner.Run(ctx, "ip", "link", "delete", "veth-l2tp996h") })
	for _, args := range [][]string{
		{"link", "set", "veth-l2tp996c", "netns", ns},
		{"addr", "add", "192.0.2.9/30", "dev", "veth-l2tp996h"},
		{"link", "set", "veth-l2tp996h", "up"},
		{"netns", "exec", ns, "ip", "addr", "add", "192.0.2.10/30", "dev", "veth-l2tp996c"},
		{"netns", "exec", ns, "ip", "link", "set", "veth-l2tp996c", "up"},
		{"netns", "exec", ns, "ip", "link", "set", "lo", "up"},
	} {
		run("ip", args...)
	}
	for _, rule := range [][]string{
		{"INPUT", "-i", "veth-l2tp996h", "-p", "udp", "--dport", "1701", "-j", "ACCEPT"},
		{"INPUT", "-i", "pp996-+", "-p", "icmp", "-j", "ACCEPT"},
	} {
		run("iptables", append([]string{"-I", rule[0], "1"}, rule[1:]...)...)
		deleteArgs := append([]string{"-D"}, rule...)
		t.Cleanup(func() { _, _ = runner.Run(ctx, "iptables", deleteArgs...) })
	}
	root, err := os.MkdirTemp("/var/lib", "netos-l2tp-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := New(runner, root)
	// The real pppd executes hooks from its system directory.
	server := config.VPNServer{ID: "qa-l2tp", Index: 996, Type: "l2tp", Name: "QA L2TP", Enabled: true,
		Subnet: "10.96.0.1/24", DefaultChannel: "direct", Config: map[string]any{"listen": "192.0.2.9", "mtu": 1400},
		Peers: []config.VPNPeer{
			{ID: "qa", Enabled: true, Address: "10.96.0.2", Credentials: map[string]string{"username": "qa-l2tp", "password": "qa-l2tp-secret"}},
			{ID: "qa2", Enabled: true, Address: "10.96.0.3", Credentials: map[string]string{"username": "qa-l2tp2", "password": "qa-l2tp-secret2"}},
		}}
	_, _, unit := s.l2tpPaths(server)
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatal("test unit already exists")
	}
	snapshots, err := capturePaths(l2tpChapSecrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.cleanupL2TP(ctx, server)
		if err := restorePaths(snapshots); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}}
	cfg.VPNServers = []config.VPNServer{server}
	if _, err := s.applyL2TP(ctx, server, cfg, false); err != nil {
		t.Fatal(err)
	}
	if err := s.writeOwned(ownedServersFor(cfg.VPNServers)); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	stamp := run("systemctl", "show", l2tpUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value")
	ppp := filepath.Join(root, "client.ppp")
	conf := filepath.Join(root, "client.conf")
	for path, data := range map[string]string{
		ppp:  "name qa-l2tp\npassword qa-l2tp-secret\nnoauth\nnodefaultroute\nnoipv6\nifname ppp-qa996\nmtu 1400\nmru 1400\n",
		conf: fmt.Sprintf("[global]\nport = 1701\n[lac qa]\nlns = 192.0.2.9\npppoptfile = %s\nautodial = yes\nredial = yes\nredial timeout = 2\n", ppp),
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	log, err := os.Create(filepath.Join(root, "client.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	client := exec.Command("ip", "netns", "exec", ns, "xl2tpd", "-D", "-c", conf, "-p", filepath.Join(root, "client.pid"), "-C", filepath.Join(root, "client.ctl"))
	client.Stdout, client.Stderr = log, log
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Process.Kill(); _ = client.Wait() })
	connected := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if _, err := runner.Run(ctx, "ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", "10.96.0.1"); err == nil {
			connected = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !connected {
		data, _ := os.ReadFile(log.Name())
		t.Fatalf("no PPP session: %s", data)
	}
	link := run("ip", "-o", "link", "show", "dev", "pp996-0a600002")
	// A second client has its own physical path and deliberately requests the
	// first client's address. Authentication must still assign its own address.
	const ns2 = "netos-l2tp996b"
	run("ip", "netns", "add", ns2)
	t.Cleanup(func() {
		out, _ := runner.Run(ctx, "ip", "netns", "pids", ns2)
		for _, pid := range strings.Fields(out) {
			_, _ = runner.Run(ctx, "kill", "-TERM", pid)
		}
		_, _ = runner.Run(ctx, "ip", "netns", "delete", ns2)
	})
	run("ip", "link", "add", "veth-l2tp996bh", "type", "veth", "peer", "name", "veth-l2tp996bc")
	t.Cleanup(func() { _, _ = runner.Run(ctx, "ip", "link", "delete", "veth-l2tp996bh") })
	for _, args := range [][]string{
		{"link", "set", "veth-l2tp996bc", "netns", ns2},
		{"addr", "add", "192.0.2.13/30", "dev", "veth-l2tp996bh"},
		{"link", "set", "veth-l2tp996bh", "up"},
		{"netns", "exec", ns2, "ip", "addr", "add", "192.0.2.14/30", "dev", "veth-l2tp996bc"},
		{"netns", "exec", ns2, "ip", "link", "set", "veth-l2tp996bc", "up"},
		{"netns", "exec", ns2, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", ns2, "ip", "route", "add", "192.0.2.9/32", "via", "192.0.2.13"},
	} {
		run("ip", args...)
	}
	rule2 := []string{"INPUT", "-i", "veth-l2tp996bh", "-p", "udp", "--dport", "1701", "-j", "ACCEPT"}
	run("iptables", append([]string{"-I", "INPUT", "1"}, rule2[1:]...)...)
	t.Cleanup(func() { _, _ = runner.Run(ctx, "iptables", append([]string{"-D"}, rule2...)...) })
	ppp2, conf2 := filepath.Join(root, "client2.ppp"), filepath.Join(root, "client2.conf")
	if err := os.WriteFile(ppp2, []byte("name qa-l2tp2\npassword qa-l2tp-secret2\nnoauth\nnodefaultroute\nnoipv6\nifname ppp-qa996b\n10.96.0.2:\nipcp-accept-local\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf2, []byte(fmt.Sprintf("[global]\nport = 1701\n[lac qa]\nlns = 192.0.2.9\npppoptfile = %s\nautodial = yes\nredial = yes\nredial timeout = 2\n", ppp2)), 0600); err != nil {
		t.Fatal(err)
	}
	client2 := exec.Command("ip", "netns", "exec", ns2, "xl2tpd", "-D", "-c", conf2, "-p", filepath.Join(root, "client2.pid"), "-C", filepath.Join(root, "client2.ctl"))
	client2.Stdout, client2.Stderr = log, log
	if err := client2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client2.Process.Kill(); _ = client2.Wait() })
	connected = false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if _, err := runner.Run(ctx, "ip", "netns", "exec", ns2, "ping", "-c", "1", "-W", "1", "10.96.0.1"); err == nil {
			connected = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !connected {
		data, _ := os.ReadFile(log.Name())
		t.Fatalf("second PPP session failed: %s", data)
	}
	if got := run("ip", "netns", "exec", ns2, "ip", "-4", "addr", "show", "dev", "ppp-qa996b"); !strings.Contains(got, "inet 10.96.0.3 ") {
		t.Fatalf("foreign requested address granted: %s", got)
	}
	run("ip", "-o", "link", "show", "dev", "pp996-0a600003")
	run("ip", "netns", "exec", ns, "ping", "-c", "2", "-W", "1", "10.96.0.1")
	changed := *cfg
	changed.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	changed.VPNServers[0].Name = "Renamed L2TP"
	changed.VPNServers[0].Config = map[string]any{"listen": "192.0.2.9", "mtu": 1380}
	actions, err := s.Plan(cfg, &changed)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("MTU change lost confirmation: %+v %v", actions, err)
	}
	changed.VPNServers[0].Config = server.Config
	savedUnit, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	actions, err = s.Plan(cfg, &changed)
	restoreErr := os.WriteFile(unit, savedUnit, 0644)
	if err != nil || restoreErr != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("repair lost confirmation: %+v %v restore=%v", actions, err, restoreErr)
	}
	for _, name := range []string{"Renamed L2TP", "Renamed L2TP", server.Name} {
		previous := *cfg
		previous.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
		server.Name = name
		cfg.VPNServers[0] = server
		actions, err := s.Plan(&previous, cfg)
		if err != nil || apply.NeedsConfirmation(actions) {
			t.Fatalf("rename confirmation: %+v %v", actions, err)
		}
		if _, err := s.applyL2TP(ctx, server, cfg, true); err != nil {
			t.Fatal(err)
		}
		if got := run("systemctl", "show", l2tpUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value"); got != stamp {
			t.Fatal("rename restarted L2TP")
		}
		if got := run("systemctl", "show", l2tpUnitName(server), "-p", "Description", "--value"); !strings.Contains(got, name) {
			t.Fatal("description not updated")
		}
		if got := run("ip", "-o", "link", "show", "dev", "pp996-0a600002"); got != link {
			t.Fatal("rename recreated PPP")
		}
		run("ip", "netns", "exec", ns, "ping", "-c", "2", "-W", "1", "10.96.0.1")
	}
	for _, channel := range []string{"alternate", "alternate", "direct"} {
		server.DefaultChannel, server.Peers[0].Channel = channel, channel
		if _, err := s.applyL2TP(ctx, server, cfg, true); err != nil {
			t.Fatal(err)
		}
		if got := run("systemctl", "show", l2tpUnitName(server), "-p", "ActiveEnterTimestampMonotonic", "--value"); got != stamp {
			t.Fatal("L2TP service restarted")
		}
		if got := run("ip", "-o", "link", "show", "dev", "pp996-0a600002"); got != link {
			t.Fatal("PPP interface changed")
		}
		run("ip", "netns", "exec", ns, "ping", "-c", "2", "-W", "1", "10.96.0.1")
	}
}
