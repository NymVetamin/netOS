//go:build linux

package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIntegrationL2TPSourceBinding(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		return string(out)
	}
	const server = "netos-l2tp-src-s"
	const client = "netos-l2tp-src-c"
	for _, ns := range []string{server, client} {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", ns).Run() })
		run("ip", "-n", ns, "link", "set", "lo", "up")
	}
	iface := config.L2TPPeerInterface(9, "10.99.0.2")
	run("ip", "-n", server, "link", "add", iface, "type", "veth", "peer", "name", "client", "netns", client)
	run("ip", "-n", server, "addr", "add", "10.99.0.1/24", "dev", iface)
	run("ip", "-n", server, "link", "set", iface, "up")
	run("ip", "-n", client, "addr", "add", "10.99.0.2/24", "dev", "client")
	run("ip", "-n", client, "addr", "add", "10.99.0.3/24", "dev", "client")
	run("ip", "-n", client, "link", "set", "client", "up")
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{Type: "l2tp", Index: 9, Enabled: true, Peers: []config.VPNPeer{{Enabled: true, Address: "10.99.0.2"}, {Enabled: true, Address: "10.99.0.3"}}}}
	apply := func() {
		t.Helper()
		b := &builder{}
		b.mangle(cfg, nil)
		cmd := exec.Command("ip", "netns", "exec", server, "iptables-restore")
		cmd.Stdin = strings.NewReader(b.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("kernel rejected rules: %v %s", err, out)
		}
	}
	ping := func(ip string, want bool) {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", client, "ping", "-I", ip, "-c", "1", "-W", "1", "10.99.0.1").CombinedOutput()
		if (err == nil) != want {
			t.Fatalf("source=%s reachable=%v want=%v: %s", ip, err == nil, want, out)
		}
	}
	apply()
	ping("10.99.0.2", true)
	ping("10.99.0.3", false)
	cfg.VPNServers[0].Peers[0].Enabled = false
	apply()
	ping("10.99.0.2", false)
	cfg.VPNServers[0].Peers[0].Enabled = true
	apply()
	ping("10.99.0.2", true)
	ping("10.99.0.3", false)
	t.Log(run("ip", "netns", "exec", server, "iptables", "-t", "mangle", "-nvL", "NETOS-L2TP"))
}
