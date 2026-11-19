//go:build linux

package routing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
)

type routeTestLog struct{ *testing.T }

func (l routeTestLog) Infof(f string, a ...any)  { l.Logf(f, a...) }
func (l routeTestLog) Warnf(f string, a ...any)  { l.Logf(f, a...) }
func (l routeTestLog) Errorf(f string, a ...any) { l.Logf(f, a...) }

// Run in a private network and mount namespace with sysfs remounted.
func TestIntegrationChannelRouteLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires isolated Linux integration environment")
	}
	for _, kind := range []string{"net", "mnt"} {
		host, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		self, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		if self == host {
			t.Fatal("requires private " + kind + " namespace")
		}
	}
	root := t.TempDir()
	oldTables, oldProtos := rtTablesPath, rtProtosPath
	rtTablesPath, rtProtosPath = filepath.Join(root, "tables"), filepath.Join(root, "protos")
	defer func() { rtTablesPath, rtProtosPath = oldTables, oldProtos }()
	ctx := context.Background()
	r := system.NewExec()
	channel := channels.New(r, root)
	channel.RTTablesPath = filepath.Join(root, "channels.tables")
	e := apply.NewEngine(routeTestLog{t}, false)
	late := &TunnelRoutes{Runner: r}
	for _, s := range []apply.Subsystem{New(r), channel, late} {
		if err := e.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	run := func(cmd string, args ...string) string {
		t.Helper()
		v, err := r.Run(ctx, cmd, args...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(v)
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "qa-wan", "type", "dummy")
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "qa-wan")
	run("ip", "link", "set", "qa-wan", "up")
	run("ip", "route", "add", "default", "dev", "qa-wan", "proto", "boot")
	private := run("wg", "genkey")
	pub, err := r.RunInput(ctx, run("wg", "genkey")+"\n", "wg", "pubkey")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Components = append(cfg.Components, config.Component{ID: "wireguard", Installed: true})
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "qa", Index: 1, Name: "qa", Type: "wireguard", Enabled: true, Mode: "tun", FailMode: "block",
		Config: map[string]any{"private_key": private, "peer_public_key": strings.TrimSpace(pub),
			"address": "10.77.1.2/32", "endpoint": "127.0.0.1:51996", "allowed_ips": []string{"0.0.0.0/0"}},
	})
	cfg.Routing.Static = []config.StaticRoute{
		{ID: "r1", Enabled: true, Destination: "10.9.0.0/24", Interface: "wg-ch1"},
		{ID: "r2", Enabled: true, Destination: "2001:db8:9::/64", Interface: "wg-ch1", Type: "unicast"},
	}
	off := *cfg
	off.Channels = append([]config.Channel(nil), cfg.Channels...)
	off.Channels[len(off.Channels)-1].Enabled = false
	applyConfig := func(c *config.Config) {
		t.Helper()
		if res := c.Validate(); res.HasErrors() {
			t.Fatalf("invalid test configuration: %+v", res.Problems)
		}
		if _, err := e.Apply(ctx, c, 1, false); err != nil {
			t.Fatal(err)
		}
	}
	check := func(active bool) {
		t.Helper()
		want := "dev qa-wan"
		if active {
			want = "dev wg-ch1"
		}
		if path := run("ip", "route", "get", "10.9.0.1"); !strings.Contains(path, want) {
			t.Fatalf("lookup %s, want %s", path, want)
		}
		for i, family := range []string{"-4", "-6"} {
			line := run("ip", family, "route", "show", "proto", "static", "exact", cfg.Routing.Static[i].Destination)
			if strings.Contains(line, "dev wg-ch1") != active {
				t.Fatalf("active %t, route %q", active, line)
			}
		}
	}
	for _, c := range []*config.Config{cfg, &off, &off, cfg, cfg} {
		applyConfig(c)
		check(c == cfg)
	}
	run("ip", "-4", "route", "del", "10.9.0.0/24", "dev", "wg-ch1")
	if late.Health(ctx, cfg) == nil {
		t.Fatal("health accepted missing route")
	}
	applyConfig(cfg)
	check(true)
	applyConfig(&off)
	broken := *cfg
	broken.IPv6.Mode = "off"
	if _, err := e.Apply(ctx, &broken, 2, false); err == nil || !strings.Contains(err.Error(), "tunnel-routes") || strings.Contains(err.Error(), "откат тоже не удался") {
		t.Fatalf("expected late IPv6 failure and successful restore: %v", err)
	}
	check(false)
	bad := *cfg
	bad.Routing.Static = append(append([]config.StaticRoute(nil), cfg.Routing.Static...), config.StaticRoute{ID: "bad", Enabled: true, Destination: "198.51.100.0/24", Interface: "unknown0"})
	for _, previous := range []*config.Config{&off, cfg} {
		applyConfig(previous)
		if res := bad.Validate(); res.HasErrors() {
			t.Fatal(res.Problems)
		}
		_, err := e.Apply(ctx, &bad, 2, false)
		if err == nil || !strings.Contains(err.Error(), "unknown0") || strings.Contains(err.Error(), "откат тоже не удался") {
			t.Fatalf("expected device error and successful restore: %v", err)
		}
		check(previous == cfg)
	}
	t.Logf("confirmed disable, enable and rollback with %d saved routes", len(cfg.Routing.Static))
}
