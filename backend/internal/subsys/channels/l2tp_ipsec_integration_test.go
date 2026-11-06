//go:build linux

package channels_test

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIntegrationL2TPIPsecChannel(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		init, _ := os.Readlink("/proc/1/ns/" + kind)
		if self == init {
			t.Fatal("refusing host namespace", kind)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return string(out)
	}
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	root, err := os.MkdirTemp("/var/lib", "netos-l2tp-ipsec-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ns := fmt.Sprintf("netos-l2c-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	defer func() {
		pids, _ := exec.Command("ip", "netns", "pids", ns).Output()
		for _, pid := range strings.Fields(string(pids)) {
			exec.Command("kill", "-KILL", pid).Run()
		}
		exec.Command("ip", "netns", "del", ns).Run()
	}()
	remote := func(args ...string) string { return run("ip", append([]string{"netns", "exec", ns}, args...)...) }
	run("ip", "link", "set", "lo", "up")
	remote("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "l2chost", "type", "veth", "peer", "name", "l2cpeer")
	run("ip", "link", "set", "l2cpeer", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "l2chost")
	run("ip", "link", "set", "l2chost", "up")
	remote("ip", "addr", "add", "192.0.2.2/24", "dev", "l2cpeer")
	remote("ip", "link", "set", "l2cpeer", "up")
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "server", Index: 1, Type: "l2tp", Enabled: true, Config: map[string]any{"listen": "192.0.2.2", "ipsec": true, "preshared_key": "test-ipsec-secret"}}}
	serverConfig, err := vpnservers.RenderIPsec(cfg)
	if err != nil {
		t.Fatal(err)
	}
	serverConf := filepath.Join(root, "server-swanctl.conf")
	write(serverConf, string(serverConfig))
	socket := "unix://" + filepath.Join(root, "server.vici")
	daemon := filepath.Join(root, "server-daemon.conf")
	write(daemon, fmt.Sprintf("charon {\n load_modular = yes\n plugins {\n include /etc/strongswan.d/charon/*.conf\n vici {\n socket = %s\n }\n }\n}\ninclude /etc/strongswan.d/*.conf\n", socket))
	start := func(command string, args ...string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command("ip", append([]string{"netns", "exec", ns, command}, args...)...)
		log, err := os.OpenFile(filepath.Join(root, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		log.Close()
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd
	}
	serverProcess := start("env", "STRONGSWAN_CONF="+daemon, "/usr/sbin/charon-systemd")
	for i := 0; i < 50; i++ {
		if conn, err := net.DialTimeout("unix", filepath.Join(root, "server.vici"), 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	remote("/usr/sbin/swanctl", "--load-all", "--uri", socket, "--file", serverConf, "--noprompt")
	// Use the server's IPsec guard before accepting PPP.
	match, rules := vpnservers.L2TPIPsecGuard(cfg.VPNServers[0])
	remote("iptables", "-t", "mangle", "-N", vpnservers.L2TPIPsecGuardChain)
	remote(append([]string{"iptables", "-t", "mangle", "-A", "PREROUTING"}, strings.Fields(match+" -j "+vpnservers.L2TPIPsecGuardChain)...)...)
	for _, rule := range rules {
		remote(append([]string{"iptables", "-t", "mangle"}, strings.Fields(rule)...)...)
	}
	chap := filepath.Join(root, "chap-secrets")
	write(chap, "test server test-password *\n")
	run("mount", "--bind", chap, "/etc/ppp/chap-secrets")
	ppp := filepath.Join(root, "server.ppp")
	write(ppp, "lcp-echo-interval 1\nlcp-echo-failure 3\nrequire-mschap-v2\nname server\nnodefaultroute\nnoipv6\nmtu 1400\nmru 1400\n")
	l2conf := filepath.Join(root, "server-l2tp.conf")
	write(l2conf, fmt.Sprintf("[global]\nport = 1701\nlisten-addr = 192.0.2.2\naccess control = no\n[lns default]\nip range = 10.253.94.2-10.253.94.20\nlocal ip = 10.253.94.1\nrequire authentication = yes\nname = server\npppoptfile = %s\n", ppp))
	start("xl2tpd", "-D", "-c", l2conf, "-p", filepath.Join(root, "server.pid"), "-C", filepath.Join(root, "server.ctl"))
	// A server daemon already owns UDP500/4500 in the client's namespace.
	localDaemon := filepath.Join(root, "local-server-daemon.conf")
	daemonText, err := os.ReadFile(daemon)
	if err != nil {
		t.Fatal(err)
	}
	localSocket := "unix://" + filepath.Join(root, "local-server.vici")
	write(localDaemon, strings.ReplaceAll(string(daemonText), socket, localSocket))
	coexist := exec.Command("env", "STRONGSWAN_CONF="+localDaemon, "/usr/sbin/charon-systemd")
	if err := coexist.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { coexist.Process.Kill(); coexist.Wait() }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(filepath.Join(root, "local-server.vici")); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(run("ss", "-lun"), ":500 ") {
		t.Fatal("coexisting IKE listener absent")
	}
	ch := config.Channel{ID: "l2c", Index: 993, Name: "L2TP IPsec test", Type: "l2tp", Mode: "tun", Enabled: true, FailMode: "block", Config: map[string]any{"server": "192.0.2.2", "username": "test", "password": "test-password", "ipsec": true, "preshared_key": "test-ipsec-secret"}}
	cfg.VPNServers = nil
	cfg.Channels = append(cfg.Channels, ch)
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}, {ID: "strongswan", Installed: true}}
	s := channels.New(system.NewExec(), filepath.Join(root, "state"))
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	// Do not modify host AppArmor policy in this isolated transport test.
	s.AppArmorDir = filepath.Join(root, "apparmor")
	s.AppArmorProfiles = filepath.Join(root, "profiles")
	units := []string{"netos-vpn-l2tp-ch993.service", "netos-l2tp-ipsec-ch993.service"}
	for _, unit := range units {
		path := filepath.Join("/etc/systemd/system", unit)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("test unit exists")
		}
		if _, err := os.Stat(path + ".d"); !os.IsNotExist(err) {
			t.Fatal("test dropin exists")
		}
		if err := os.MkdirAll(path+".d", 0755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(path+".d", "network.conf"), fmt.Sprintf("[Service]\nNetworkNamespacePath=/proc/%d/ns/net\n", os.Getpid()))
	}
	defer func() {
		for _, unit := range units {
			exec.Command("systemctl", "disable", "--now", unit).Run()
			os.Remove(filepath.Join("/etc/systemd/system", unit))
			os.RemoveAll(filepath.Join("/etc/systemd/system", unit+".d"))
		}
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", append([]string{"reset-failed"}, units...)...).Run()
	}()
	apply := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		defer cancel()
		return s.Apply(ctx, cfg)
	}
	ping := func() {
		t.Helper()
		run("ip", "route", "replace", "10.253.94.1/32", "dev", channels.InterfaceName(ch))
		run("ping", "-c", "1", "-W", "3", "10.253.94.1")
	}
	if err := apply(); err != nil {
		log, _ := os.ReadFile(filepath.Join(root, "server.log"))
		t.Fatalf("initial: %v server=%s", err, log)
	}
	ipsecFile := filepath.Join(root, "state", "netos-l2tp-ipsec-ch993.conf")
	info, err := os.Stat(ipsecFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("IPsec secret permissions", err)
	}
	ping()
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	pid := run("systemctl", "show", units[0], "-p", "MainPID", "--value")
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	ping()
	if pid != run("systemctl", "show", units[0], "-p", "MainPID", "--value") {
		t.Fatal("repeat restarted PPP")
	}
	t.Log("initial and unchanged repeat PASS; wrong key next")
	ch.Config["preshared_key"] = "wrong-test-key"
	if err := apply(); err == nil {
		t.Fatal("wrong PSK accepted")
	}
	t.Log("wrong key rejected; checking rollback")
	ping() // rollback must restore the previous connection before retry
	ch.Config["preshared_key"] = "test-ipsec-secret"
	if err := apply(); err != nil {
		t.Fatal("retry", err)
	}
	ping()
	// Keep PPP running while IPsec is gone; plaintext must be dropped locally.
	run("systemctl", "stop", units[1])
	if strings.TrimSpace(run("ip", "xfrm", "state", "list", "nokeys", "reqid", "70993")) != "" {
		t.Fatal("channel kernel state survived stop")
	}
	for _, rule := range channels.L2TPChannelIPsecRules(ch) {
		run("iptables", append([]string{"-t", "mangle", "-C"}, strings.Fields(rule)[1:]...)...)
	}
	run("python3", "-c", `import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)
try: s.sendto(struct.pack('!HHHH',20993,1701,9,0)+b'x',('192.0.2.2',1701))
except PermissionError: pass # OUTPUT DROP may report EPERM to a local sender
`)
	remote("python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'plaintext',('192.0.2.1',20993))
`)
	for _, chain := range []string{"OUTPUT", "PREROUTING"} {
		table := run("iptables", "-t", "mangle", "-nvxL", chain)
		dropped := false
		for _, line := range strings.Split(table, "\n") {
			if strings.Contains(line, "20993") && strings.Contains(line, "DROP") {
				fields := strings.Fields(line)
				dropped = len(fields) > 0 && fields[0] != "0"
			}
		}
		if !dropped {
			t.Fatal("plaintext not dropped", chain, table)
		}
	}
	run("systemctl", "start", units[1])
	run("systemctl", "restart", units[0])
	for i := 0; i < 100; i++ {
		out, _ := exec.Command("ip", "-4", "addr", "show", "dev", channels.InterfaceName(ch)).CombinedOutput()
		if strings.Contains(string(out), "inet ") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	ping()
	// Simulate daemon failure: systemd and the tunnel must recover without manual PPP restart.
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); s.Run(monitorCtx, func() *config.Config { return cfg }) }()
	defer stopMonitor()
	run("systemctl", "kill", "--signal=KILL", units[1])
	recovered := false
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		if exec.Command("ping", "-m", fmt.Sprint(channels.Mark(ch)), "-c", "1", "-W", "1", "10.253.94.1").Run() == nil {
			recovered = true
			break
		}
	}
	stopMonitor()
	<-monitorDone
	if !recovered {
		t.Fatal("IPsec daemon crash did not recover automatically")
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal("health after daemon crash", err)
	}
	// Explicitly switching to plaintext must remove client guards and daemon.
	remote("iptables", "-t", "mangle", "-F", vpnservers.L2TPIPsecGuardChain)
	serverProcess.Process.Signal(syscall.SIGTERM)
	serverProcess.Wait()
	ch.Config["ipsec"] = false
	if err := apply(); err != nil {
		t.Fatal("plain transition", err)
	}
	ping()
	serverProcess = start("env", "STRONGSWAN_CONF="+daemon, "/usr/sbin/charon-systemd")
	for i := 0; i < 50; i++ {
		if conn, err := net.DialTimeout("unix", filepath.Join(root, "server.vici"), 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	remote("/usr/sbin/swanctl", "--load-all", "--uri", socket, "--file", serverConf, "--noprompt")
	ch.Config["ipsec"] = true
	for _, rule := range rules {
		remote(append([]string{"iptables", "-t", "mangle"}, strings.Fields(rule)...)...)
	}
	if err := apply(); err != nil {
		t.Fatal("secure transition", err)
	}
	ping()
	cfg.Channels = cfg.Channels[:len(cfg.Channels)-1]
	if err := apply(); err != nil {
		t.Fatal("remove", err)
	}
	for _, unit := range units {
		if _, err := os.Stat(filepath.Join("/etc/systemd/system", unit)); !os.IsNotExist(err) {
			t.Fatal("unit survived", unit)
		}
	}
	for _, rule := range channels.L2TPChannelIPsecRules(ch) {
		if err := exec.Command("iptables", append([]string{"-t", "mangle", "-C"}, strings.Fields(rule)[1:]...)...).Run(); err == nil {
			t.Fatal("guard survived removal")
		}
	}
	if _, err := os.Stat(ipsecFile); !os.IsNotExist(err) {
		t.Fatal("secret survived removal")
	}
	t.Log("netOS server IPsec/PPP authentication, ping, repeat, wrong PSK rollback/retry, interrupted transport guard/reconnect and removal PASS")
}
