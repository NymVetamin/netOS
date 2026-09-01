package sysctl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type sysctlRunner struct {
	commands []string
}

func (r *sysctlRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	return "", nil
}

func (r *sysctlRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func withSysctlPaths(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	oldConf, oldModules, oldIPv6 := confPath, modulesPath, ipv6ConfPath
	oldProc, oldNet := procSysPath, netClassPath
	confPath = filepath.Join(root, "etc", "sysctl.d", "99-netos.conf")
	modulesPath = filepath.Join(root, "etc", "modules-load.d", "netos.conf")
	ipv6ConfPath = filepath.Join(root, "etc", "sysctl.d", "99-netos-ipv6.conf")
	procSysPath = filepath.Join(root, "proc", "sys")
	netClassPath = filepath.Join(root, "sys", "class", "net")
	t.Cleanup(func() {
		confPath, modulesPath, ipv6ConfPath = oldConf, oldModules, oldIPv6
		procSysPath, netClassPath = oldProc, oldNet
	})
	return root
}

func seedSysctls(t *testing.T, values map[string]string) {
	t.Helper()
	for key := range values {
		path := filepath.Join(procSysPath, filepath.Join(strings.Split(key, ".")...))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unset"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoreMetadataPlanApplyAndHealth(t *testing.T) {
	withSysctlPaths(t)
	cfg := config.Default()
	runner := &sysctlRunner{}
	core := NewCore(runner)
	if core.Name() != "sysctl" {
		t.Fatalf("Name = %q", core.Name())
	}
	actions, err := core.Plan(nil, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "create" {
		t.Fatalf("missing-file Plan = %#v, %v", actions, err)
	}
	seedSysctls(t, core.values(cfg))
	if err := core.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || runner.commands[0] != "modprobe nf_conntrack" {
		t.Fatalf("commands = %#v", runner.commands)
	}
	if err := core.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	actions, err = core.Plan(cfg, cfg)
	if err != nil || len(actions) != 0 {
		t.Fatalf("clean Plan = %#v, %v", actions, err)
	}
	if err := os.WriteFile(modulesPath, []byte("drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	actions, err = core.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("module drift Plan = %#v, %v", actions, err)
	}
	writeRawSysctl(t, "net.ipv4.conf.all.rp_filter", "0")
	if err := core.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "rp_filter") {
		t.Fatalf("drift Health = %v", err)
	}
}

func TestCoreApplyStopsAtFileAndKernelErrors(t *testing.T) {
	for _, stage := range []string{"modules", "conf", "kernel"} {
		t.Run(stage, func(t *testing.T) {
			root := withSysctlPaths(t)
			cfg := config.Default()
			core := NewCore(&sysctlRunner{})
			seedSysctls(t, core.values(cfg))
			switch stage {
			case "modules":
				modulesPath = root
			case "conf":
				confPath = root
			case "kernel":
				key := "net.core.default_qdisc"
				path := filepath.Join(procSysPath, filepath.Join(strings.Split(key, ".")...))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := core.Apply(context.Background(), cfg); err == nil {
				t.Fatalf("expected %s failure", stage)
			}
		})
	}
}

func TestIPv6PlanApplyHealthOffAndPassthrough(t *testing.T) {
	for _, mode := range []string{"off", "passthrough"} {
		t.Run(mode, func(t *testing.T) {
			withSysctlPaths(t)
			cfg := config.Default()
			cfg.IPv6.Mode = mode
			ipv6 := NewIPv6(&sysctlRunner{})
			if ipv6.Name() != "ipv6" {
				t.Fatalf("Name = %q", ipv6.Name())
			}
			actions, err := ipv6.Plan(cfg, cfg)
			if err != nil || len(actions) != 1 || actions[0].Kind != "create" || !actions[0].Disruptive {
				t.Fatalf("missing-file Plan = %#v, %v", actions, err)
			}
			seedSysctls(t, ipv6.values(cfg))
			for _, name := range []string{"lo", "eth0"} {
				if err := os.MkdirAll(filepath.Join(netClassPath, name), 0o755); err != nil {
					t.Fatal(err)
				}
				if name != "lo" {
					for _, key := range []string{"disable_ipv6", "accept_ra", "autoconf"} {
						seedSysctls(t, map[string]string{"net.ipv6.conf." + name + "." + key: ""})
					}
				}
			}
			if err := ipv6.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := ipv6.Health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			actions, err = ipv6.Plan(cfg, cfg)
			if err != nil || len(actions) != 0 {
				t.Fatalf("clean Plan = %#v, %v", actions, err)
			}
			writeRawSysctl(t, "net.ipv6.conf.eth0.accept_ra", "9")
			if err := ipv6.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "eth0.accept_ra") {
				t.Fatalf("interface drift Health = %v", err)
			}
		})
	}
}

func TestIPv6ReturnsConfigProcAndInterfaceErrors(t *testing.T) {
	withSysctlPaths(t)
	cfg := config.Default()
	ipv6 := NewIPv6(&sysctlRunner{})
	seedSysctls(t, ipv6.values(cfg))
	ipv6ConfPath = filepath.Dir(ipv6ConfPath)
	if err := ipv6.Apply(context.Background(), cfg); err == nil {
		t.Fatal("expected config write error")
	}
	withSysctlPaths(t)
	seedSysctls(t, ipv6.values(cfg))
	netClassPath = filepath.Join(t.TempDir(), "missing")
	if err := ipv6.Apply(context.Background(), cfg); err == nil {
		t.Fatal("expected interface enumeration error")
	}
	if err := ipv6.Health(context.Background(), cfg); err != nil {
		t.Fatalf("missing IPv6 sysfs should be tolerated by Health: %v", err)
	}
}

func TestSysctlPrimitivesMissingWhitespaceAndReadErrors(t *testing.T) {
	withSysctlPaths(t)
	if err := writeSysctl("net.missing.key", "1"); err != nil {
		t.Fatalf("missing key = %v", err)
	}
	seedSysctls(t, map[string]string{"net.test.list": ""})
	writeRawSysctl(t, "net.test.list", "1\t  2\n")
	if err := checkValues(map[string]string{"net.test.list": "1 2", "net.optional.missing": "3"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(procSysPath, "net", "test", "list")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := readSysctl("net.test.list"); err == nil {
		t.Fatal("expected read error for directory")
	}
	if err := checkValues(map[string]string{"net.test.list": "1"}); err == nil {
		t.Fatal("expected check read error")
	}
}

func writeRawSysctl(t *testing.T, key, value string) {
	t.Helper()
	path := filepath.Join(procSysPath, filepath.Join(strings.Split(key, ".")...))
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}
