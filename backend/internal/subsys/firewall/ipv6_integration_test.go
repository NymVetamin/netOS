//go:build linux

package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Режим «Разрешить» на настоящем ip6tables: набор применяется, живой
// ip6tables-save совпадает с ним после приведения (иначе проверка после
// применения откатывала бы конфигурацию), аплинк не достаёт до закрытого
// порта роутера, а ответы на соединения самого роутера проходят.
func TestIntegrationIPv6PassthroughFilter(t *testing.T) {
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
	ns := fmt.Sprintf("v6wan%d", os.Getpid())
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	run("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	run("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "peer0")
	run("ip", "link", "set", "peer0", "netns", ns)
	run("ip", "-6", "addr", "add", "2001:db8:6::1/64", "dev", "wan0", "nodad")
	run("ip", "link", "set", "wan0", "up")
	run("ip", "link", "set", "lo", "up")
	run("ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	run("ip", "netns", "exec", ns, "ip", "-6", "addr", "add", "2001:db8:6::2/64", "dev", "peer0", "nodad")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "peer0", "up")

	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Interfaces = []config.Interface{{ID: "uplink", Name: "wan0"}}
	cfg.WANs = []config.WAN{{ID: "isp", Name: "isp", Interface: "uplink", Enabled: true, Proto: "static", Metric: 100}}
	cfg.Normalize()
	rules := buildIPv6(cfg)
	cmd := exec.Command("ip6tables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ip6tables-restore: %s %v\n%s", out, err, rules)
	}
	live := run("ip6tables-save")
	if !rulesetMatches(live, rules) {
		t.Fatalf("живые правила не совпали со сгенерированными\nlive:\n%s\nexpected:\n%s", live, rules)
	}

	// Закрытый порт роутера: системных правил для него нет.
	listener, err := net.Listen("tcp6", "[::]:18022")
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
			c.Close()
		}
	}()
	dial := `exec 3<>/dev/tcp/2001:db8:6::1/18022`
	if out, err := r.Run(ctx, "ip", "netns", "exec", ns, "timeout", "3", "bash", "-c", dial); err == nil {
		t.Fatalf("аплинк подключился к закрытому порту роутера по IPv6: %s", out)
	}

	// Ответы на соединение самого роутера проходят.
	run("ip", "netns", "exec", ns, "sh", "-c", "timeout 5 python3 -c 'import socket;s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"2001:db8:6::2\",18080));s.listen();c,_=s.accept();c.close()' >/dev/null 2>&1 &")
	// Отказ в соединении приходит мгновенно, пока слушатель ещё запускается:
	// попытки разнесены по времени.
	var conn net.Conn
	for i := 0; i < 30 && conn == nil; i++ {
		if conn, err = net.DialTimeout("tcp6", "[2001:db8:6::2]:18080", 500*time.Millisecond); err != nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if conn == nil {
		t.Fatalf("роутер не установил соединение наружу по IPv6: %v", err)
	}
	conn.Close()

	// Разрешение системного правила должно зависеть от зоны, а не только
	// от Enabled. Политика LAN — DROP, чтобы успех доказывал само правило.
	lanNS := fmt.Sprintf("v6lan%d", os.Getpid())
	run("ip", "netns", "add", lanNS)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", lanNS).Run() })
	run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "lanpeer")
	run("ip", "link", "set", "lanpeer", "netns", lanNS)
	run("ip", "-6", "addr", "add", "2001:db8:7::1/64", "dev", "lan0", "nodad")
	run("ip", "link", "set", "lan0", "up")
	run("ip", "netns", "exec", lanNS, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	run("ip", "netns", "exec", lanNS, "ip", "-6", "addr", "add", "2001:db8:7::2/64", "dev", "lanpeer", "nodad")
	run("ip", "netns", "exec", lanNS, "ip", "link", "set", "lanpeer", "up")
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "lan", Name: "lan0"})
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", Zone: "lan", Enabled: true}}
	for i := range cfg.Firewall.Zones {
		cfg.Firewall.Zones[i].Policy = "drop"
	}
	for _, id := range []string{config.RuleSSH, config.RulePanel} {
		for _, zone := range []string{"global", "lan", "wan", "lan", "vpn"} {
			for i := range cfg.Firewall.Rules {
				rule := &cfg.Firewall.Rules[i]
				if rule.ID == config.RuleSSH || rule.ID == config.RulePanel {
					rule.Enabled = rule.ID == id
					rule.Zone, rule.DstPort = zone, "18022"
				}
			}
			rules := buildIPv6(cfg)
			for repeat := 0; repeat < 2; repeat++ {
				cmd := exec.Command("ip6tables-restore")
				cmd.Stdin = strings.NewReader(rules)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s/%s restore: %s %v", id, zone, out, err)
				}
				if !rulesetMatches(run("ip6tables-save"), rules) {
					t.Fatalf("%s/%s live rules differ", id, zone)
				}
			}
			for _, source := range []struct{ ns, addr, zone string }{
				{ns, "2001:db8:6::1", "wan"}, {lanNS, "2001:db8:7::1", "lan"},
			} {
				out, err := exec.Command("ip", "netns", "exec", source.ns, "timeout", "1", "bash", "-c", "exec 3<>/dev/tcp/"+source.addr+"/18022").CombinedOutput()
				allowed := zone == "global" || zone == source.zone
				if allowed && err != nil {
					t.Fatalf("%s/%s from %s blocked: %s %v", id, zone, source.zone, out, err)
				}
				if !allowed {
					if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 124 {
						t.Fatalf("%s/%s from %s: expected drop timeout, got %s %v", id, zone, source.zone, out, err)
					}
				}
			}
		}
	}
}
