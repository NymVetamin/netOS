//go:build linux

package firewall

import (
	"bufio"
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestIntegrationInternetBlock(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("root isolated namespace required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if self == init {
		t.Fatal("refusing host namespace")
	}
	r := system.NewExec()
	ctx := context.Background()
	run := func(name string, args ...string) string {
		t.Helper()
		o, e := r.Run(ctx, name, args...)
		if e != nil {
			t.Fatalf("%s %v: %s %v", name, args, o, e)
		}
		return o
	}
	names := []string{fmt.Sprintf("nbc%d", os.Getpid()), fmt.Sprintf("nbd%d", os.Getpid())}
	for i, ns := range names {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		dev := []string{"lan0", "dst0"}[i]
		run("ip", "link", "add", dev, "type", "veth", "peer", "name", "peer0")
		run("ip", "link", "set", "peer0", "netns", ns)
		subnet := []string{"192.0.2.", "10.22.0."}[i]
		run("ip", "addr", "add", subnet+"1/24", "dev", dev)
		run("ip", "link", "set", dev, "up")
		run("ip", "netns", "exec", ns, "ip", "addr", "add", subnet+"2/24", "dev", "peer0")
		run("ip", "netns", "exec", ns, "ip", "link", "set", "peer0", "up")
		run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", subnet+"1")
	}
	run("ip", "netns", "exec", names[0], "ip", "link", "set", "peer0", "address", "02:00:00:00:00:02")
	run("ip", "netns", "exec", names[1], "ip", "addr", "add", "198.51.100.2/32", "dev", "peer0")
	run("ip", "route", "add", "198.51.100.2/32", "via", "10.22.0.2")
	run("sysctl", "-w", "net.ipv4.ip_forward=1")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "source", Name: "lan0"}, {ID: "inside", Name: "dst0"}}
	cfg.Networks = []config.Network{
		{ID: "source", Interface: "source", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"},
		{ID: "local", Interface: "inside", Zone: "lan", Enabled: true, RouterAddress: "10.22.0.1/24"},
	}
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, config.FirewallRule{ID: "internal", Enabled: true, Zone: "lan", Flow: "forward", DstIP: "10.22.0.0/24", Action: "accept"})
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02"}}
	apply := func() {
		t.Helper()
		var b builder
		b.filter(cfg, buildZoneMap(cfg))
		cmd := exec.Command("iptables-restore")
		cmd.Stdin = strings.NewReader(b.String())
		if o, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("restore: %s %v", o, e)
		}
	}
	ping := func(ip string, want bool) {
		t.Helper()
		o, e := r.Run(ctx, "ip", "netns", "exec", names[0], "ping", "-c", "1", "-W", "1", ip)
		if (e == nil) != want {
			t.Fatalf("ping %s expected %v: %s %v", ip, want, o, e)
		}
	}
	echo := exec.Command("ip", "netns", "exec", names[1], "python3", "-u", "-c", `import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',18999));s.listen()
print('ready',flush=True)
def serve(c):
 try:
  while True:
   x=c.recv(1024)
   if not x:break
   c.sendall(x)
 finally:c.close()
while True:
 c,a=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()`)
	out, _ := echo.StdoutPipe()
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { echo.Process.Kill(); echo.Wait() }()
	if !bufio.NewScanner(out).Scan() {
		t.Fatal("echo failed")
	}
	persistent := func(address string) (io.WriteCloser, *bufio.Scanner) {
		cmd := exec.Command("ip", "netns", "exec", names[0], "python3", "-u", "-c", `import socket,sys
s=socket.create_connection((sys.argv[1],18999),3);s.settimeout(1)
for line in sys.stdin:
 try:s.sendall(line.encode());print(s.recv(1024).decode().strip(),flush=True)
 except socket.timeout:print('blocked',flush=True)`, address)
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
		return in, bufio.NewScanner(out)
	}
	checkStream := func(in io.WriteCloser, scan *bufio.Scanner, want string) {
		t.Helper()
		fmt.Fprintln(in, "echo")
		done := make(chan bool, 1)
		go func() { done <- scan.Scan() }()
		select {
		case ok := <-done:
			if !ok || scan.Text() != want {
				t.Fatalf("stream expected %s got %s", want, scan.Text())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stream timeout")
		}
	}
	apply()
	externalIn, externalOut := persistent("198.51.100.2")
	internalIn, internalOut := persistent("10.22.0.2")
	checkStream(externalIn, externalOut, "echo")
	checkStream(internalIn, internalOut, "echo")
	ping("198.51.100.2", true)
	ping("10.22.0.2", true)
	cfg.Clients[0].Channel = config.InternetBlockChannel
	for i := 0; i < 2; i++ {
		apply()
		checkStream(externalIn, externalOut, "blocked")
		checkStream(internalIn, internalOut, "echo")
		ping("198.51.100.2", false)
		ping("10.22.0.2", true)
		ping("192.0.2.1", true)
	}
	cfg.Clients[0].Channel = "direct"
	apply()
	ping("198.51.100.2", true)
	freshIn, freshOut := persistent("198.51.100.2")
	checkStream(freshIn, freshOut, "echo")

	// A global deny must still beat a zone accept; a global accept must still
	// beat a zone deny, but neither can bypass the per-client restriction.
	baseRules := append([]config.FirewallRule(nil), cfg.Firewall.Rules...)
	global := config.FirewallRule{ID: "priority", Enabled: true, Zone: "global", Flow: "forward", DstIP: "198.51.100.2", Action: "drop"}
	cfg.Firewall.Rules = append([]config.FirewallRule{global}, baseRules...)
	apply()
	ping("198.51.100.2", false)
	global.Action = "accept"
	cfg.Firewall.Rules[0] = global
	cfg.Firewall.Zones[0].Policy = "drop"
	apply()
	ping("198.51.100.2", true)
	cfg.Clients[0].Channel = config.InternetBlockChannel
	apply()
	ping("198.51.100.2", false)
	ping("10.22.0.2", true)
	cfg.Clients[0].Blocked = true
	apply()
	ping("10.22.0.2", false)
	ping("192.0.2.1", false)
	cfg.Clients[0].Blocked = false
	cfg.Clients[0].Channel = "direct"
	apply()
	ping("198.51.100.2", true)
	ping("192.0.2.1", true)
	// Unclassified ingress retains global permissions and MAC restrictions.
	cfg.Networks[0].Enabled = false
	apply()
	ping("198.51.100.2", true)
	cfg.Clients[0].Channel = config.InternetBlockChannel
	apply()
	ping("198.51.100.2", false)
	cfg.Networks[0].Enabled = true
	cfg.Firewall.Enabled = false
	apply()
	ping("198.51.100.2", false)
	ping("10.22.0.2", true)
	cfg.Clients[0].Channel = "direct"
	apply()
	ping("198.51.100.2", true)
	cfg.Firewall.Enabled = true
	cfg.Firewall.Zones[0].Policy = "accept"
	cfg.Firewall.Rules = baseRules
	// Real packets with the OpenConnect wildcard interface selector. Tunnel
	// negotiation is outside this test; the complete generated filter is used.
	run("ip", "link", "set", "lan0", "name", "vpns2a")
	cfg.Networks[0].Enabled = false
	cfg.VPNServers = []config.VPNServer{{ID: "vpn", Type: "ocserv", Index: 2, Enabled: true, Port: 443, Subnet: "192.0.2.1/24", Peers: []config.VPNPeer{{ID: "p", Enabled: true, Address: "192.0.2.2"}}}}
	apply()
	vpnIn, vpnOut := persistent("198.51.100.2")
	checkStream(vpnIn, vpnOut, "echo")
	cfg.VPNServers[0].Peers[0].Channel = config.InternetBlockChannel
	for i := 0; i < 2; i++ {
		apply()
		checkStream(vpnIn, vpnOut, "blocked")
		ping("198.51.100.2", false)
		ping("10.22.0.2", true)
		ping("192.0.2.1", true)
	}
	cfg.VPNServers[0].Peers[0].Channel = "direct"
	apply()
	ping("198.51.100.2", true)
	cfg.VPNServers = nil
	run("ip", "link", "set", "vpns2a", "name", "lan0")
	cfg.Networks[0].Enabled = true
	apply()
	run("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0", "net.ipv6.conf.all.forwarding=1")
	run("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "wanpeer")
	run("ip", "link", "set", "wanpeer", "netns", names[1])
	run("ip", "link", "set", "wan0", "up")
	run("ip", "-6", "addr", "add", "2001:db8:9::1/64", "dev", "wan0", "nodad")
	run("ip", "-6", "addr", "add", "fd00:1::1/64", "dev", "lan0", "nodad")
	run("ip", "-6", "addr", "add", "fd00:2::1/64", "dev", "dst0", "nodad")
	for i, ns := range names {
		run("ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
		prefix := []string{"fd00:1::", "fd00:2::"}[i]
		run("ip", "netns", "exec", ns, "ip", "-6", "addr", "add", prefix+"2/64", "dev", "peer0", "nodad")
		run("ip", "netns", "exec", ns, "ip", "-6", "route", "add", "default", "via", prefix+"1")
	}
	run("ip", "netns", "exec", names[1], "ip", "link", "set", "wanpeer", "up")
	run("ip", "netns", "exec", names[1], "ip", "-6", "addr", "add", "2001:db8:9::2/64", "dev", "wanpeer", "nodad")
	cfg.IPv6.Mode = "passthrough"

	apply6 := func() {
		t.Helper()
		cmd := exec.Command("ip6tables-restore")
		cmd.Stdin = strings.NewReader(buildIPv6(cfg))
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("IPv6 restore: %s %v", out, e)
		}
	}
	apply6()
	// Fresh IPv6 links complete neighbour discovery before the baseline probe.
	for i := 0; i < 3; i++ {
		if _, e := r.Run(ctx, "ip", "netns", "exec", names[0], "ping", "-c", "1", "-W", "2", "2001:db8:9::2"); e == nil {
			break
		}
	}
	ping("2001:db8:9::2", true)
	cfg.Clients[0].Channel = config.InternetBlockChannel
	apply6()
	ping("2001:db8:9::2", false)
	ping("fd00:2::2", true)
	ping("fd00:1::1", true)
	cfg.Clients[0].Channel = "direct"
	apply6()
	ping("2001:db8:9::2", true)

}
