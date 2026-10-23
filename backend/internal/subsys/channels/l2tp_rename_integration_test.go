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

func TestIntegrationL2TPChannelRename(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and NETOS_INTEGRATION=1")
	}
	for _, bin := range []string{"ip", "xl2tpd", "pppd", "ping"} {
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
		return strings.TrimSpace(out)
	}
	const ns, host, peer = "netos-l2tp-rename", "l2r-host", "l2r-peer"
	if _, err := os.Stat("/var/run/netns/" + ns); !os.IsNotExist(err) {
		t.Fatal("test namespace exists")
	}
	run("ip", "netns", "add", ns)
	defer func() {
		pids, _ := r.Run(ctx, "ip", "netns", "pids", ns)
		for _, pid := range strings.Fields(pids) {
			_, _ = r.Run(ctx, "kill", "-TERM", pid)
		}
		_, _ = r.Run(ctx, "ip", "netns", "delete", ns)
	}()
	run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
	defer r.Run(ctx, "ip", "link", "delete", host)
	run("ip", "link", "set", peer, "netns", ns)
	run("ip", "addr", "add", "192.0.2.149/30", "dev", host)
	run("ip", "link", "set", host, "up")
	remote := func(args ...string) string { return run("ip", append([]string{"netns", "exec", ns}, args...)...) }
	remote("ip", "link", "set", "lo", "up")
	remote("ip", "addr", "add", "192.0.2.150/30", "dev", peer)
	remote("ip", "link", "set", peer, "up")
	run("iptables", "-I", "INPUT", "1", "-i", host, "-j", "ACCEPT")
	defer r.Run(ctx, "iptables", "-D", "INPUT", "-i", host, "-j", "ACCEPT")
	root, err := os.MkdirTemp("/var/lib/netos", "l2tp-rename-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ppp, conf := filepath.Join(root, "remote.ppp"), filepath.Join(root, "remote.conf")
	if err := os.WriteFile(ppp, []byte("noauth\nnodefaultroute\nnoipv6\nmtu 1400\nmru 1400\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte(fmt.Sprintf("[global]\nport = 1701\nlisten-addr = 192.0.2.150\naccess control = no\n[lns default]\nip range = 10.253.94.2-10.253.94.2\nlocal ip = 10.253.94.1\nrequire authentication = no\npppoptfile = %s\n", ppp)), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(root, "remote.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command("ip", "netns", "exec", ns, "xl2tpd", "-D", "-c", conf, "-p", filepath.Join(root, "remote.pid"), "-C", filepath.Join(root, "remote.ctl"))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	s := New(r, filepath.Join(root, "state"))
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	ch := config.Channel{ID: "l2tp-rename", Index: 994, Name: "Before", Enabled: true, Type: "l2tp", Mode: "tun", FailMode: "block", Config: map[string]any{"server": "192.0.2.150", "username": "test", "password": "test", "mtu": 1400}}
	_, _, unitPath := s.l2tpPaths(ch)
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatal("test unit exists")
	}
	defer s.removeChannel(ctx, ownedChannel{Name: InterfaceName(ch), Index: ch.Index, Type: "l2tp", Unit: l2tpUnitName(ch)})
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "l2tp", Installed: true}}
	cfg.Channels = append(cfg.Channels, ch)
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	stamp := run("systemctl", "show", l2tpUnitName(ch), "-p", "ActiveEnterTimestampMonotonic", "--value")
	link := run("ip", "-o", "link", "show", "dev", InterfaceName(ch))
	changed := *cfg
	changed.Channels = append([]config.Channel(nil), cfg.Channels...)
	index := len(changed.Channels) - 1
	changed.Channels[index].Name = "After"
	changed.Channels[index].FailMode = "direct"
	actions, err := s.Plan(cfg, &changed)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("mixed fail mode lost confirmation: %+v %v", actions, err)
	}
	changed.Channels[index].FailMode = ch.FailMode
	changed.Channels[index].Config = map[string]any{}
	for k, v := range ch.Config {
		changed.Channels[index].Config[k] = v
	}
	changed.Channels[index].Config["mtu"] = 1380
	actions, err = s.Plan(cfg, &changed)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("mixed MTU lost confirmation: %+v %v", actions, err)
	}
	changed.Channels[index].Config = ch.Config
	saved, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	actions, err = s.Plan(cfg, &changed)
	restoreErr := os.WriteFile(unitPath, saved, 0644)
	if err != nil || restoreErr != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("repair lost confirmation: %+v %v restore=%v", actions, err, restoreErr)
	}
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
		if run("systemctl", "show", l2tpUnitName(ch), "-p", "ActiveEnterTimestampMonotonic", "--value") != stamp {
			t.Fatal("rename restarted L2TP")
		}
		if run("ip", "-o", "link", "show", "dev", InterfaceName(ch)) != link {
			t.Fatal("rename replaced PPP link")
		}
		run("ping", "-c", "2", "-W", "2", "10.253.94.1")
	}
	cfg.Channels[len(cfg.Channels)-1].Config["mtu"] = 1380
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if run("systemctl", "show", l2tpUnitName(ch), "-p", "ActiveEnterTimestampMonotonic", "--value") == stamp {
		t.Fatal("MTU change did not restart L2TP")
	}
	run("ping", "-c", "2", "-W", "2", "10.253.94.1")
}
