//go:build linux

package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Run only in a disposable network namespace on the authorized test machine.
func TestIntegrationClientAccountingExit(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == host {
		t.Fatal("refusing host namespace")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		b, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, b)
		}
		return string(b)
	}
	peers := []struct{ name, link, router, client string }{
		{fmt.Sprintf("nm-lan-%d", os.Getpid()), "lan0", "192.0.2.1/24", "192.0.2.2/24"},
		{fmt.Sprintf("nm-vpn-%d", os.Getpid()), "wg-srv1", "198.51.100.1/24", "198.51.100.2/24"},
	}
	for _, p := range peers {
		run("ip", "netns", "add", p.name)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", p.name).Run() })
		run("ip", "link", "add", p.link, "type", "veth", "peer", "name", "peer0", "netns", p.name)
		run("ip", "addr", "add", p.router, "dev", p.link)
		run("ip", "link", "set", p.link, "up")
		run("ip", "-n", p.name, "addr", "add", p.client, "dev", "peer0")
		run("ip", "-n", p.name, "link", "set", "peer0", "up")
		run("ip", "-n", p.name, "link", "set", "lo", "up")
		run("ip", "-n", p.name, "route", "add", "default", "via", strings.Split(p.router, "/")[0])
	}
	run("sysctl", "-qw", "net.ipv4.ip_forward=1")
	// External destination reached through the same interface as VPN clients.
	run("ip", "-n", peers[1].name, "addr", "add", "203.0.113.9/32", "dev", "lo")
	run("ip", "route", "add", "203.0.113.9/32", "via", "198.51.100.2")
	c := &config.Config{Interfaces: []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}}, Networks: []config.Network{{Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}, VPNServers: []config.VPNServer{{Index: 1, Type: "wireguard", Enabled: true, Subnet: "198.51.100.1/24", Peers: []config.VPNPeer{{Enabled: true, Address: "198.51.100.2", UseAsChannel: true}}}}}
	c.TrafficMonitor.Enabled = true
	apply := func(exists bool) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(Render(c, exists))
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("nft: %v %s", e, b)
		}
	}
	snapshot := func() map[string]uint64 {
		t.Helper()
		var doc struct {
			Objects []struct {
				Set *struct {
					Name string `json:"name"`
					Elem []struct {
						Elem struct {
							Val     string `json:"val"`
							Counter struct {
								Bytes uint64 `json:"bytes"`
							} `json:"counter"`
						} `json:"elem"`
					} `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if e := json.Unmarshal([]byte(run("nft", "-j", "list", "table", "inet", Table)), &doc); e != nil {
			t.Fatal(e)
		}
		out := map[string]uint64{}
		for _, o := range doc.Objects {
			if o.Set != nil {
				for _, e := range o.Set.Elem {
					out[o.Set.Name+":"+e.Elem.Val] = e.Elem.Counter.Bytes
				}
			}
		}
		return out
	}
	apply(false)
	for _, dst := range []string{"198.51.100.2", "203.0.113.9"} {
		run("ip", "netns", "exec", peers[0].name, "ping", "-n", "-c", "2", "-W", "2", dst)
	}
	before := snapshot()
	for _, key := range []string{"up4:192.0.2.2", "down4:192.0.2.2", "up4:198.51.100.2", "down4:198.51.100.2"} {
		if before[key] == 0 {
			t.Errorf("missing client bytes: %s", key)
		}
	}
	for _, key := range []string{"up4:203.0.113.9", "down4:203.0.113.9"} {
		if _, ok := before[key]; ok {
			t.Errorf("external endpoint counted as client: %s", key)
		}
	}
	apply(true)
	after := snapshot()
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Error("reapply changed counters")
	}
	run("ip", "netns", "exec", peers[1].name, "ping", "-n", "-c", "2", "-W", "2", "192.0.2.2")
	if snapshot()["up4:198.51.100.2"] <= before["up4:198.51.100.2"] {
		t.Error("VPN client stopped accounting after reapply")
	}
	for _, n := range []int{4, 256} {
		c.Interfaces = c.Interfaces[:1]
		c.Networks = c.Networks[:1]
		for i := 1; i < n; i++ {
			name := fmt.Sprintf("unused%d", i)
			c.Interfaces = append(c.Interfaces, config.Interface{ID: name, Name: name, Enabled: true})
			c.Networks = append(c.Networks, config.Network{Interface: name, RouterAddress: fmt.Sprintf("10.0.%d.1/24", i), Enabled: true})
		}
		for repeat := 0; repeat < 3; repeat++ {
			start := time.Now()
			apply(true)
			applyTime := time.Since(start)
			start = time.Now()
			run("ip", "netns", "exec", peers[0].name, "ping", "-n", "-f", "-c", "2000", "-W", "2", "203.0.113.9")
			t.Logf("networks=%d repeat=%d render+apply=%s ping2000=%s", n, repeat, applyTime, time.Since(start))
		}
	}
	c.TrafficMonitor.Enabled = false
	apply(true)
	if exec.Command("nft", "list", "table", "inet", Table).Run() == nil {
		t.Error("disable retained table")
	}
	c.TrafficMonitor.Enabled = true
	apply(false)
	if len(snapshot()) != 0 {
		t.Error("reenable retained old counters")
	}
}
