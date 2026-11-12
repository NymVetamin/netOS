//go:build linux

package api

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/system"
)

// Run in a disposable VM: unshare --mount --net env NETOS_AWG_INTEGRATION=1
// ./api.test -test.run '^TestIntegrationSharedWireGuardStatus$' -test.v
func TestIntegrationSharedWireGuardStatus(t *testing.T) {
	if os.Getenv("NETOS_AWG_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("explicit isolated root integration only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, e := os.Readlink("/proc/self/ns/" + kind)
		host, h := os.Readlink("/proc/1/ns/" + kind)
		if e != nil || h != nil || self == host {
			t.Fatal("refusing host namespace", kind)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "set", "lo", "up")
	ns := fmt.Sprintf("netos-status-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	defer exec.Command("ip", "netns", "del", ns).Run()
	remote := func(name string, args ...string) string {
		t.Helper()
		return run("ip", append([]string{"netns", "exec", ns, name}, args...)...)
	}
	run("ip", "link", "add", "underlay", "type", "veth", "peer", "name", "remote")
	run("ip", "link", "set", "remote", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/30", "dev", "underlay")
	run("ip", "link", "set", "underlay", "up")
	remote("ip", "link", "set", "lo", "up")
	remote("ip", "addr", "add", "192.0.2.2/30", "dev", "remote")
	remote("ip", "link", "set", "remote", "up")
	for i, kind := range []string{"wireguard", "amneziawg"} {
		t.Run(kind, func(t *testing.T) {
			tool := "wg"
			params := ""
			if kind == "amneziawg" {
				tool = "awg"
				params = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nH1 = 100\nH2 = 200\nH3 = 300\nH4 = 400\n"
			}
			key := func() (string, string) {
				priv := run(tool, "genkey")
				cmd := exec.Command(tool, "pubkey")
				cmd.Stdin = strings.NewReader(priv)
				pub, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				return priv, strings.TrimSpace(string(pub))
			}
			priv, pub := key()
			rp, rpub := key()
			root := t.TempDir()
			link := "wg-srv1"
			peer := "peer1"
			port := fmt.Sprint(51820 + i)
			subnet := fmt.Sprintf("10.45.%d", i)
			localConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\n%s[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.2:%s\nAllowedIPs = %s.2/32\n", priv, params, rpub, port, subnet)
			remoteConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %s\n%s[Peer]\nPublicKey = %s\nAllowedIPs = %s.1/32\n", rp, port, params, pub, subnet)
			lp, rpath := filepath.Join(root, "local.conf"), filepath.Join(root, "remote.conf")
			if err := os.WriteFile(lp, []byte(localConf), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rpath, []byte(remoteConf), 0600); err != nil {
				t.Fatal(err)
			}
			run("ip", "link", "add", link, "type", kind)
			remote("ip", "link", "add", peer, "type", kind)
			defer exec.Command("ip", "link", "del", link).Run()
			defer exec.Command("ip", "netns", "exec", ns, "ip", "link", "del", peer).Run()
			run(tool, "setconf", link, lp)
			remote(tool, "setconf", peer, rpath)
			run("ip", "addr", "add", subnet+".1/24", "dev", link)
			remote("ip", "addr", "add", subnet+".2/24", "dev", peer)
			run("ip", "link", "set", link, "up")
			remote("ip", "link", "set", peer, "up")
			cfg := &config.Config{VPNServers: []config.VPNServer{{ID: "server", Index: 1, Type: "wireguard", Enabled: true, Config: map[string]any{}}}, Channels: []config.Channel{{ID: "exit", Type: "wireguard", Enabled: true, WireGuardPeer: &config.WireGuardPeerChannel{ServerID: "server", ServerIndex: 1, PeerID: "peer"}}}}
			if kind == "amneziawg" {
				cfg.VPNServers[0].Config["amneziawg"] = map[string]any{}
			}
			s := &Server{Collector: &runtime.Collector{Runner: system.NewExec()}}
			stats := []runtime.InterfaceStat{{Name: link, Up: true}}
			check := func(want bool) {
				t.Helper()
				_, got := s.liveLinks(context.Background(), cfg, stats)
				if len(got) != 1 || got[0]["up"] != want {
					t.Fatalf("real %s status=%v want=%v", kind, got, want)
				}
			}
			check(false) // Interface UP without a handshake is not an established tunnel.
			run("ping", "-n", "-c", "2", "-W", "5", "-I", link, subnet+".2")
			check(true)
			check(true)
			s.ChannelHealth = downProbe(true)
			check(false)
			s.ChannelHealth = nil
			check(true)
			run("ip", "link", "del", link)
			check(false) // stale collector snapshot, actual command failure
			t.Log("native traffic, handshake, repeat, probe failure/recovery and missing link PASS")
		})
	}
}
