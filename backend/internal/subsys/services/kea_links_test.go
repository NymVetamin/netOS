package services

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestKeaLateLinkAndRecovery(t *testing.T) {
	cfg := providerTestConfig()
	cfg.DHCP.Provider = "kea"
	r := &serviceRunner{}
	m := NewKeaLinkMonitor(r)
	state := map[string]string{}
	m.scan = func(*config.Config) (map[string]string, error) { return state, nil }
	poll := func(want int) {
		t.Helper()
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if len(r.commands) != want {
			t.Fatalf("commands=%v, want %d", r.commands, want)
		}
	}
	for i := 0; i < 120; i++ {
		poll(0) // Waiting for a cable must not exhaust any retry budget.
	}
	state = map[string]string{"br0": "5:192.168.50.1"}
	poll(1)
	for i := 0; i < 120; i++ {
		poll(1) // No systemctl calls in steady state.
	}
	state = map[string]string{}
	poll(1) // A lost carrier does not restart/reload Kea.
	state = map[string]string{"br0": "5:192.168.50.1"}
	poll(2)
	state = map[string]string{"br0": "6:192.168.50.1"}
	poll(3) // Recreated interface with the same name.
	state = map[string]string{"br0": "6:192.168.50.1,192.168.51.1"}
	poll(4) // Address appeared after carrier.
	for _, command := range r.commands {
		if command != "systemctl kill --kill-whom=main --signal=HUP "+keaUnit {
			t.Fatalf("unexpected mutation: %s", command)
		}
	}
	cfg.DHCP.Provider = "dnsmasq"
	m.scan = func(*config.Config) (map[string]string, error) { t.Fatal("scanned non-Kea config"); return nil, nil }
	poll(4)
	if m.ready != nil {
		t.Fatal("disabled provider retained state")
	}
}

type keaLinkRunner struct {
	serviceRunner
	fail bool
}

func (r *keaLinkRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.serviceRunner.Run(ctx, name, args...)
	if r.fail {
		return "", errors.New("signal failed")
	}
	return "", nil
}

func TestKeaLinkFailureIsRetried(t *testing.T) {
	cfg := providerTestConfig()
	cfg.DHCP.Provider = "kea"
	r := &keaLinkRunner{fail: true}
	m := NewKeaLinkMonitor(r)
	m.scan = func(*config.Config) (map[string]string, error) {
		return map[string]string{"br0": "1:192.168.50.1"}, nil
	}
	if err := m.Reconcile(context.Background(), cfg); err == nil {
		t.Fatal("signal failure was hidden")
	}
	r.fail = false
	if err := m.Reconcile(context.Background(), cfg); err != nil || len(r.commands) != 2 {
		t.Fatalf("retry: err=%v commands=%v", err, r.commands)
	}
	m.scan = func(*config.Config) (map[string]string, error) { return nil, errors.New("scan failed") }
	if err := m.Reconcile(context.Background(), cfg); err == nil || len(r.commands) != 2 || len(m.ready) != 1 {
		t.Fatal("scan failure lost acknowledged state or signaled Kea")
	}
}

func TestKeaReadyLinksSelectOnlyUsablePoolAddresses(t *testing.T) {
	cfg := providerTestConfig()
	ifaces := []net.Interface{
		{Name: "br0", Index: 5, Flags: net.FlagUp | net.FlagRunning},
		{Name: "unrelated", Index: 6, Flags: net.FlagUp | net.FlagRunning},
	}
	ip := "192.168.50.1/24"
	addresses := func(i net.Interface) ([]net.Addr, error) {
		if i.Name != "br0" {
			t.Fatal("queried unrelated interface")
		}
		host, a, _ := net.ParseCIDR(ip)
		a.IP = host
		return []net.Addr{a}, nil
	}
	check := func(want map[string]string) {
		t.Helper()
		got, err := keaReadyLinks(cfg, ifaces, addresses)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ready=%v err=%v want=%v", got, err, want)
		}
	}
	check(map[string]string{"br0": "5:192.168.50.1"})
	ifaces[0].Flags = net.FlagUp
	check(map[string]string{})
	ifaces[0].Flags = net.FlagUp | net.FlagRunning
	ip = "192.168.60.1/24"
	check(map[string]string{})
	ip = "192.168.50.1/24"
	cfg.Networks[0].DHCPPool.Enabled = false
	check(map[string]string{})
	cfg.Networks[0].DHCPPool.Enabled = true
	cfg.Interfaces[0].Enabled = false
	check(map[string]string{})
}
