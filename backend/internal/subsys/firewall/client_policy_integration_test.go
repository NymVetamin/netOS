//go:build linux

package firewall

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Exercise both working and blackholed exits: reverse-path validation can
// reject a new management connection when its client mark selects a blackhole.
func TestIntegrationClientPolicyPreservesRouterAccess(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing host network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ctx = apply.WithManagementConnection(ctx, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
	r := system.NewExec()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := r.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %s %v", name, args, out, err)
		}
		return out
	}
	ns := fmt.Sprintf("netos-confirm-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", ns).Run() })
	run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "peer0")
	run("ip", "link", "set", "peer0", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "lan0")
	run("ip", "link", "set", "lan0", "up")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "peer0", "address", "02:00:00:00:00:02")
	run("ip", "netns", "exec", ns, "ip", "addr", "add", "192.0.2.2/24", "dev", "peer0")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "peer0", "up")
	run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "192.0.2.1")
	run("ip", "link", "add", "wg-ch1", "type", "dummy")
	run("ip", "link", "set", "wg-ch1", "up")
	run("ip", "route", "add", "default", "dev", "wg-ch1", "table", "1001")
	run("ip", "rule", "add", "priority", "10001", "fwmark", "0x1001", "lookup", "1001")
	run("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.lan0.rp_filter=2", "net.ipv4.conf.all.src_valid_mark=1", "net.ipv4.conf.lan0.src_valid_mark=1")
	cfg, _ := configuredFirewall(t)
	cfg.Channels = []config.Channel{{ID: "direct", Type: "direct", Enabled: true}, {ID: "vpn", Type: "wireguard", Index: 1, Enabled: true}}
	cfg.Clients = []config.Client{{ID: "client", MAC: "02:00:00:00:00:02", Channel: "direct"}}
	s := New(r, t.TempDir())
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "192.0.2.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	program := "import socket,sys\ns=socket.create_connection(('192.0.2.1',int(sys.argv[1])),3)\ns.settimeout(3)\nf=s.makefile('rb')\nfor line in sys.stdin:\n s.sendall(line.encode()); print(f.readline().decode().rstrip(),flush=True)\n"
	start := func() (io.WriteCloser, *bufio.Reader, func()) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", program, port)
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return input, bufio.NewReader(output), func() {
			input.Close()
			if err := cmd.Wait(); err != nil {
				t.Errorf("client: %v", err)
			}
		}
	}
	check := func(input io.Writer, output *bufio.Reader, message string) {
		t.Helper()
		if _, err := fmt.Fprintln(input, message); err != nil {
			t.Fatal(err)
		}
		got, err := output.ReadString('\n')
		if err != nil || strings.TrimSpace(got) != message {
			t.Fatalf("TCP access lost: %q %v", got, err)
		}
	}
	input, output, finish := start()
	defer finish()
	check(input, output, "initial")
	for _, mode := range []string{"client", "segment", "policy", "direct"} {
		data, _ := json.Marshal(cfg)
		var before config.Config
		if err := json.Unmarshal(data, &before); err != nil {
			t.Fatal(err)
		}
		cfg.Clients[0].Channel = ""
		cfg.Networks[0].DefaultChannel = ""
		cfg.Policies = nil
		switch mode {
		case "client":
			cfg.Clients[0].Channel = "vpn"
		case "segment":
			cfg.Networks[0].DefaultChannel = "vpn"
		case "policy":
			cfg.Policies = []config.Policy{{ID: "p", Enabled: true, Channel: "vpn", SrcIP: "192.0.2.2"}}
		}
		actions, err := s.PlanContext(ctx, &before, cfg)
		if err != nil {
			t.Fatal(err)
		}
		for i := range actions {
			actions[i].Subsystem = s.Name()
		}
		if len(actions) == 0 || apply.NeedsConfirmation(actions) {
			t.Fatalf("working route plan=%+v", actions)
		}
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		t.Logf("working exit: %s", mode)
		check(input, output, "existing-"+mode)
		freshIn, freshOut, closeFresh := start()
		check(freshIn, freshOut, "new-"+mode)
		closeFresh()
	}
	run("ip", "route", "del", "default", "table", "1001")
	run("ip", "route", "add", "blackhole", "default", "table", "1001")
	before := *cfg
	before.Clients = append([]config.Client(nil), cfg.Clients...)
	cfg.Clients[0].Channel = "vpn"
	actions, err := s.PlanContext(ctx, &before, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := range actions {
		actions[i].Subsystem = s.Name()
	}
	if !apply.NeedsConfirmation(actions) {
		t.Fatal("blackhole channel lost confirmation")
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	connect := "import socket,sys; socket.create_connection(('192.0.2.1',int(sys.argv[1])),1).close()"
	if out, err := r.Run(ctx, "ip", "netns", "exec", ns, "python3", "-c", connect, port); err == nil {
		t.Fatalf("expected reverse-path rejection on blackhole: %s", out)
	}
	// Isolate the cause without changing any packet rules or routes.
	run("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lan0.rp_filter=0")
	run("ip", "netns", "exec", ns, "python3", "-c", connect, port)
	run("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.lan0.rp_filter=2")
	cfg.Clients[0].Channel = "direct"
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	run("ip", "netns", "exec", ns, "python3", "-c", connect, port)
}
