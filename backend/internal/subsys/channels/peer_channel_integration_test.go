//go:build linux

package channels_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardPeerChannel(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		host, _ := os.Readlink("/proc/1/ns/" + kind)
		if self == host {
			t.Fatal("refusing host namespace")
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "set", "lo", "up")
	run("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	root := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ns := map[string]string{}
	for _, n := range []string{"vps", "lan", "client", "internet"} {
		name := fmt.Sprintf("netos-wgexit-%s-%d", n, os.Getpid())
		ns[n] = name
		run("ip", "netns", "add", name)
		defer exec.Command("ip", "netns", "del", name).Run()
		run("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")
	}
	remote := func(n string, args ...string) string {
		return run("ip", append([]string{"netns", "exec", ns[n]}, args...)...)
	}
	// Three isolated hosts, including a normal client on the same WG server.
	for i, n := range []string{"vps", "lan", "client"} {
		host, peer := "dut"+n, "peer"+n
		run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
		run("ip", "link", "set", peer, "netns", ns[n])
		prefix := fmt.Sprintf("192.0.%d.", i+2)
		run("ip", "addr", "add", prefix+"1/24", "dev", host)
		run("ip", "link", "set", host, "up")
		remote(n, "ip", "addr", "add", prefix+"2/24", "dev", peer)
		remote(n, "ip", "link", "set", peer, "up")
		remote(n, "ip", "route", "add", "default", "via", prefix+"1")
	}
	remote("vps", "sysctl", "-w", "net.ipv4.ip_forward=1")
	remote("vps", "ip", "link", "add", "uplink", "type", "veth", "peer", "name", "internet")
	remote("vps", "ip", "link", "set", "internet", "netns", ns["internet"])
	remote("vps", "ip", "addr", "add", "198.51.100.1/24", "dev", "uplink")
	remote("vps", "ip", "link", "set", "uplink", "up")
	remote("internet", "ip", "addr", "add", "198.51.100.2/24", "dev", "internet")
	remote("internet", "ip", "link", "set", "internet", "up")
	remote("vps", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "uplink", "-j", "MASQUERADE")
	key := func(n string) (string, string) {
		priv := run("wg", "genkey")
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = strings.NewReader(priv)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		write(n+".key", priv)
		return priv, strings.TrimSpace(string(out))
	}
	serverPrivate, serverPublic := key("server")
	vpsPrivate, vpsPublic := key("vps")
	clientPrivate, clientPublic := key("client")
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "s", Index: 1, Name: "WG", Enabled: true, Type: "wireguard", Port: 51820, Subnet: "10.234.0.1/24", Config: map[string]any{"private_key": serverPrivate}, Peers: []config.VPNPeer{
		{ID: "vps", Name: "VPS", Enabled: true, Address: "10.234.0.2", UseAsChannel: true, Credentials: map[string]string{"public_key": vpsPublic}},
		{ID: "client", Name: "Client", Enabled: true, Address: "10.234.0.3", Credentials: map[string]string{"public_key": clientPublic}},
	}}}
	cfg.Normalize()
	ch := cfg.Channels[len(cfg.Channels)-1]
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "dutlan", Type: "physical", Enabled: true}, {ID: "vps", Name: "dutvps", Type: "physical", Enabled: true}, {ID: "client", Name: "dutclient", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "vps", Interface: "vps", Enabled: true}, {ID: "client", Interface: "client", Enabled: true}}
	run("ip", "route", "add", "default", "via", "192.0.2.2")
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Interface: "lan", Enabled: true, Zone: "lan", RouterAddress: "192.0.3.1/24", DefaultChannel: ch.ID}}
	cfg.VPNServers[0].Peers[1].Channel = ch.ID
	cfg.Firewall.Enabled = true
	ctx := context.Background()
	runner := system.NewExec()
	cs := channels.New(runner, filepath.Join(root, "channels"))
	cs.RTTablesPath = filepath.Join(root, "tables")
	vs := vpnservers.New(runner, filepath.Join(root, "servers"))
	finish := channels.PeerRoutes{S: cs}
	apply := func() {
		t.Helper()
		if err := cs.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := vs.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.VPNServers[0].Peers[0].UseAsChannel {
			guard := run("iptables", "-t", "mangle", "-S", "NETOS-WGEXIT1")
			if strings.Count(guard, "-j DROP") != 1 {
				t.Fatal("guard absent or duplicated before firewall apply", guard)
			}
			run("iptables", "-t", "mangle", "-C", "PREROUTING", "-i", "wg-srv1", "-j", "NETOS-WGEXIT1")
		}
		if err := finish.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		rules, err := firewall.Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = runner.RunInput(ctx, rules.IPv4, "iptables-restore"); err != nil {
			t.Fatal(err)
		}
		if err = cs.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	// Real application traffic across the VPS, not just ICMP.
	service := exec.Command("ip", "netns", "exec", ns["internet"], "python3", "-u", "-c", `import http.server,socket,threading
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'wg-exit-check'*8192
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.2',18081))
 while True:
  data,addr=s.recvfrom(65535);s.sendto(data,addr)
threading.Thread(target=udp,daemon=True).start()
http.server.HTTPServer(('198.51.100.2',18080),Handler).serve_forever()`)
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { service.Process.Kill(); service.Wait() }()
	// netOS knows no endpoint until each remote initiates.
	if endpoints := run("wg", "show", "wg-srv1", "endpoints"); !strings.Contains(endpoints, "(none)") {
		t.Fatal(endpoints)
	}
	for i, n := range []string{"vps", "client"} {
		private := vpsPrivate
		allowed := "10.234.0.1/32"
		endpoint := "192.0.2.1:51820"
		if n == "client" {
			private = clientPrivate
			allowed = "0.0.0.0/0"
			endpoint = "192.0.4.1:51820"
		}
		remote(n, "ip", "link", "add", "wg0", "type", "wireguard")
		conf := write(n+".conf", fmt.Sprintf("[Interface]\nPrivateKey = %s\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 1\n", private, serverPublic, endpoint, allowed))
		remote(n, "wg", "setconf", "wg0", conf)
		remote(n, "ip", "addr", "add", fmt.Sprintf("10.234.0.%d/32", i+2), "dev", "wg0")
		remote(n, "ip", "link", "set", "wg0", "up")
		remote(n, "ip", "route", "add", "10.234.0.1/32", "dev", "wg0")
		if n == "client" {
			remote(n, "ip", "route", "add", "198.51.100.2/32", "dev", "wg0")
		}
	}
	ping := func(n, dst string, success bool) {
		t.Helper()
		args := []string{"netns", "exec", ns[n], "ping", "-n", "-c", "1", "-W", "1", dst}
		var err error
		var out []byte
		for i := 0; i < 40; i++ {
			out, err = exec.Command("ip", args...).CombinedOutput()
			if (err == nil) == success {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s -> %s expected %v: %s %v", n, dst, success, out, err)
	}
	ping("vps", "10.234.0.1", true)
	ping("client", "10.234.0.1", true)
	ping("lan", "198.51.100.2", true)
	ping("client", "198.51.100.2", true)
	ch.Probe.Targets = []string{"198.51.100.2"}
	if !cs.Probe(ctx, ch, channels.InterfaceName(ch)) {
		t.Fatal("bound channel probe failed")
	}
	for _, client := range []string{"lan", "client"} {
		remote(client, "python3", "-c", `import urllib.request,socket
assert urllib.request.urlopen('http://198.51.100.2:18080',timeout=5).read()==b'wg-exit-check'*8192
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.sendto(b'wg-udp-check',('198.51.100.2',18081));assert s.recv(1024)==b'wg-udp-check'`)
	}
	t.Log("PASS TCP HTTP body and UDP echo from LAN and ordinary WG client")
	t.Log("PASS incoming initiation, LAN and same-server WG transit, VPS forwarding/NAT, channel probe")
	apply()
	ping("lan", "198.51.100.2", true)
	ping("client", "10.234.0.1", true)
	remote("vps", "ip", "link", "set", "wg0", "down")
	ping("lan", "198.51.100.2", false)
	remote("vps", "ip", "link", "set", "wg0", "up")
	remote("vps", "ip", "route", "replace", "10.234.0.1/32", "dev", "wg0")
	ping("vps", "10.234.0.1", true)
	ping("lan", "198.51.100.2", true)
	// Arbitrary addresses admitted by default AllowedIPs must not become LAN clients.
	remote("vps", "ip", "addr", "add", "203.0.113.9/32", "dev", "lo")
	out, err := exec.Command("ip", "netns", "exec", ns["vps"], "ping", "-I", "203.0.113.9", "-c", "1", "-W", "1", "10.234.0.1").CombinedOutput()
	if err == nil {
		t.Fatalf("spoof admitted: %s\n%s\n%s", out, run("iptables", "-t", "mangle", "-L", "NETOS-WGEXIT1", "-nv"), remote("vps", "ip", "route", "get", "10.234.0.1", "from", "203.0.113.9"))
	}
	t.Log("PASS repeated apply, outage/recovery and unsolicited source guard")
	// Deleting the shared interface simulates server recreation; channel tables
	// must remain fail-closed and recover after the server recreates its link.
	run("ip", "link", "del", "wg-srv1")
	ping("lan", "198.51.100.2", false)
	apply()
	ping("vps", "10.234.0.1", true)
	ping("lan", "198.51.100.2", true)
	// Optional no-NAT mode: the VPS explicitly accepts and routes client prefixes.
	cfg.Firewall.NAT = []config.NATRule{{ID: "channel-nat-" + ch.ID, System: true, Direction: "source", Interface: "wg-srv1", Enabled: false}}
	remote("vps", "wg", "set", "wg0", "peer", serverPublic, "allowed-ips", "10.234.0.1/32,10.234.0.3/32,192.0.3.0/24")
	remote("vps", "ip", "route", "add", "192.0.3.0/24", "dev", "wg0")
	remote("vps", "ip", "route", "add", "10.234.0.3/32", "dev", "wg0")
	run("conntrack", "-F")
	apply()
	ping("lan", "198.51.100.2", true)
	ping("client", "198.51.100.2", true)
	cfg.Firewall.NAT[0].Enabled = true
	run("conntrack", "-F")
	apply()
	ping("lan", "198.51.100.2", true)
	t.Log("PASS NAT off with explicit VPS return routes and NAT re-enable")

	cfg.Networks[0].DefaultChannel = "direct"
	cfg.VPNServers[0].Peers[1].Channel = "direct"
	cfg.VPNServers[0].Peers[0].UseAsChannel = false
	cfg.Normalize()
	apply()
	run("wg", "show", "wg-srv1")
	ping("client", "10.234.0.1", true)
	allowed := run("wg", "show", "wg-srv1", "allowed-ips")
	if strings.Contains(allowed, "0.0.0.0/0") {
		t.Fatal(allowed)
	}
	t.Log("PASS interface recreation and exit removal without deleting server or ordinary client")
}
