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
	listener, err := net.Listen("tcp6", "[2001:db8:6::1]:18022")
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
}
