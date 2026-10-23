//go:build linux

package channels

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardChannelRenameTunnel(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and NETOS_INTEGRATION=1")
	}
	for _, bin := range []string{"ip", "wg", "iptables", "ping"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " unavailable")
		}
	}
	ctx := context.Background()
	r := system.NewExec()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := r.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		return out
	}
	keypair := func() (string, string) {
		private := strings.TrimSpace(run("wg", "genkey"))
		public, err := r.RunInput(ctx, private+"\n", "wg", "pubkey")
		if err != nil {
			t.Fatal(err)
		}
		return private, strings.TrimSpace(public)
	}
	private, public := keypair()
	remotePrivate, remotePublic := keypair()
	const ns, host, peer = "netos-wg-rename", "wgr-host", "wgr-peer"
	if _, err := os.Stat("/var/run/netns/" + ns); !os.IsNotExist(err) {
		t.Fatal("test namespace already exists")
	}
	if _, err := os.Stat("/sys/class/net/" + host); !os.IsNotExist(err) {
		t.Fatal("test link already exists")
	}
	run("ip", "netns", "add", ns)
	defer r.Run(ctx, "ip", "netns", "delete", ns)
	run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
	defer r.Run(ctx, "ip", "link", "delete", host)
	run("ip", "link", "set", peer, "netns", ns)
	run("ip", "addr", "add", "192.0.2.145/30", "dev", host)
	run("ip", "link", "set", host, "up")
	remote := func(args ...string) string { return run("ip", append([]string{"netns", "exec", ns}, args...)...) }
	remote("ip", "link", "set", "lo", "up")
	remote("ip", "addr", "add", "192.0.2.146/30", "dev", peer)
	remote("ip", "link", "set", peer, "up")
	remote("ip", "link", "add", "wg-remote", "type", "wireguard")
	root := t.TempDir()
	remoteConf := filepath.Join(root, "remote.conf")
	if err := os.WriteFile(remoteConf, []byte(fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51996\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.253.96.2/32\n", remotePrivate, public)), 0600); err != nil {
		t.Fatal(err)
	}
	remote("wg", "setconf", "wg-remote", remoteConf)
	remote("ip", "addr", "add", "10.253.96.1/24", "dev", "wg-remote")
	remote("ip", "link", "set", "wg-remote", "up")
	run("iptables", "-I", "INPUT", "1", "-i", host, "-j", "ACCEPT")
	defer r.Run(ctx, "iptables", "-D", "INPUT", "-i", host, "-j", "ACCEPT")
	s := New(r, filepath.Join(root, "state"))
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	ch := config.Channel{ID: "rename", Index: 996, Name: "Before", Type: "wireguard", Enabled: true, Mode: "tun", FailMode: "block",
		Config: map[string]any{"address": "10.253.96.2/32", "private_key": private, "peer_public_key": remotePublic, "endpoint": "192.0.2.146:51996", "allowed_ips": []string{"10.253.96.1/32"}}}
	if s.linkExists(InterfaceName(ch)) {
		t.Fatal("test channel already exists")
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, ch)
	defer s.removeChannel(ctx, ownedChannel{Name: InterfaceName(ch), Index: ch.Index, Type: "wireguard"})
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	run("ip", "route", "add", "10.253.96.1/32", "dev", InterfaceName(ch))
	ping := func() { run("ping", "-c", "2", "-W", "2", "10.253.96.1") }
	ping()
	handshake := run("wg", "show", InterfaceName(ch), "latest-handshakes")
	if strings.HasSuffix(strings.TrimSpace(handshake), "\t0") {
		t.Fatal("no handshake")
	}
	port := run("wg", "show", InterfaceName(ch), "listen-port")
	for _, name := range []string{"After", "After", "Before"} {
		previous := *cfg
		previous.Channels = append([]config.Channel(nil), cfg.Channels...)
		cfg.Channels[len(cfg.Channels)-1].Name = name
		actions, err := s.Plan(&previous, cfg)
		if err != nil || apply.NeedsConfirmation(actions) {
			t.Fatalf("healthy rename requires confirmation: %+v %v", actions, err)
		}
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		ping()
		if got := run("wg", "show", InterfaceName(ch), "latest-handshakes"); got != handshake {
			t.Fatal("rename changed handshake")
		}
		if got := run("wg", "show", InterfaceName(ch), "listen-port"); got != port {
			t.Fatal("rename changed source port")
		}
	}
}
