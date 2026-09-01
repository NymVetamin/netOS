package netiface

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func TestSubsystemNames(t *testing.T) {
	if NewInterfaces(&wanRunner{}).Name() != "interfaces" ||
		NewNetworks(&wanRunner{}).Name() != "networks" || NewWAN(&wanRunner{}).Name() != "wan" {
		t.Fatal("subsystem name changed")
	}
}

func TestInterfacesPlanEveryActionAndDisruptionClass(t *testing.T) {
	old := config.Default()
	old.Interfaces = []config.Interface{
		{ID: "physical", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "soft", Name: "br-old", Type: "bridge", Enabled: true},
		{ID: "delete", Name: "br-delete", Type: "bridge", Enabled: true},
		{ID: "gone-physical", Name: "eth9", Type: "physical", Enabled: true},
	}
	newCfg := config.Default()
	newCfg.Interfaces = []config.Interface{
		{ID: "physical", Name: "eth0", Type: "physical", Enabled: true, MTU: 1400},
		{ID: "soft", Name: "br-new", Type: "bridge", Enabled: true},
		{ID: "create", Name: "vlan10", Type: "vlan", Parent: "physical", VLANID: 10, Enabled: true},
	}
	actions, err := NewInterfaces(&wanRunner{}).Plan(old, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	assertAction(t, actions, "update", "eth0", false)
	assertAction(t, actions, "update", "br-new", true)
	assertAction(t, actions, "create", "vlan10", false)
	assertAction(t, actions, "delete", "br-delete", true)
	if findAction(actions, "delete", "eth9") != nil {
		t.Fatal("physical port deletion was planned as a kernel link deletion")
	}
	if action := findAction(actions, "create", "vlan10"); action == nil || !strings.Contains(action.Detail, "VLAN 10") {
		t.Fatalf("VLAN plan lacks useful detail: %#v", action)
	}
}

func TestNetworksPlanCreateUpdateDelete(t *testing.T) {
	old := config.Default()
	old.Networks = []config.Network{
		{ID: "update", Name: "LAN", Interface: "br0", RouterAddress: "10.0.0.1/24", Enabled: true},
		{ID: "delete", Name: "Guest", Interface: "br1", RouterAddress: "10.1.0.1/24", Enabled: true},
	}
	newCfg := config.Default()
	newCfg.Networks = []config.Network{
		{ID: "update", Name: "LAN", Interface: "br0", RouterAddress: "10.0.2.1/24", Enabled: true},
		{ID: "create", Name: "IoT", Interface: "br2", RouterAddress: "10.2.0.1/24", Enabled: true},
	}
	actions, err := NewNetworks(&wanRunner{}).Plan(old, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	assertAction(t, actions, "update", "LAN", true)
	assertAction(t, actions, "create", "IoT", false)
	assertAction(t, actions, "delete", "Guest", true)
}

func TestWANPlanCreateUpdateDelete(t *testing.T) {
	old := config.Default()
	old.WANs = []config.WAN{
		{ID: "update", Name: "Primary", Proto: "dhcp", Enabled: true, Metric: 100},
		{ID: "delete", Name: "Backup", Proto: "static", Enabled: true, Metric: 200},
	}
	newCfg := config.Default()
	newCfg.WANs = []config.WAN{
		{ID: "update", Name: "Primary", Proto: "dhcp", Enabled: true, Metric: 101},
		{ID: "create", Name: "Tunnel", Proto: "l2tp", Enabled: true, Metric: 300},
	}
	actions, err := NewWAN(&wanRunner{}).Plan(old, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	assertAction(t, actions, "update", "Primary", true)
	assertAction(t, actions, "create", "Tunnel", true)
	assertAction(t, actions, "delete", "Backup", true)
}

func TestNetworksApplyAddsAndThenRemovesOnlyOwnedAddress(t *testing.T) {
	newFakeNet(t, "lan0")
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if command == "ip -4 -o addr show dev lan0" {
			return "2: lan0 inet 198.18.0.1/32 scope global lan0\n", nil
		}
		return "", nil
	})
	s := NewNetworks(runner)
	s.OwnedAddressPath = filepath.Join(t.TempDir(), "owned-network-addresses.json")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "network", Name: "LAN", Interface: "lan", RouterAddress: "10.0.0.1/24", Enabled: true}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "ip addr add 10.0.0.1/24 dev lan0") || strings.Contains(joined, "198.18.0.1/32") && strings.Contains(joined, "addr del 198.18.0.1/32") {
		t.Fatalf("network address apply is not exact:\n%s", joined)
	}
	commands = nil
	cfg.Networks = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// The fake live output intentionally does not contain the just-added owned
	// address; cleanup must not issue a failing del for an already absent item.
	if strings.Contains(strings.Join(commands, "\n"), "addr del") {
		t.Fatalf("absent owned address was deleted anyway: %v", commands)
	}
	data, err := os.ReadFile(s.OwnedAddressPath)
	if err != nil || string(data) != "[]\n" {
		t.Fatalf("final network ownership = %q (%v)", data, err)
	}
}

func TestPrepareWANOwnershipKeepsOldAndNew(t *testing.T) {
	s := NewWAN(&wanRunner{})
	dir := t.TempDir()
	s.OwnedAddressPath = filepath.Join(dir, "addresses.json")
	s.OwnedRoutePath = filepath.Join(dir, "routes.json")
	if err := os.WriteFile(s.OwnedAddressPath, []byte(`[{"interface":"old0","address":"192.0.2.2/24"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.OwnedRoutePath, []byte(`[{"gateway":"192.0.2.1","interface":"old0","metric":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareStaticAddressOwnership([]ownedWANAddress{{Interface: "new0", Address: "198.51.100.2/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareStaticRouteOwnership([]ownedWANRoute{{Gateway: "198.51.100.1", Interface: "new0", Metric: 20}}); err != nil {
		t.Fatal(err)
	}
	addresses, err := s.readOwnedWANAddresses()
	if err != nil || len(addresses) != 2 {
		t.Fatalf("provisional addresses = %#v (%v)", addresses, err)
	}
	routes, err := s.readOwnedWANRoutes()
	if err != nil || len(routes) != 2 {
		t.Fatalf("provisional routes = %#v (%v)", routes, err)
	}
}

func TestWaitDHCPExactLeaseSuccessTimeoutAndCancellation(t *testing.T) {
	oldRuntime := dhcpRuntimeDir
	dhcpRuntimeDir = t.TempDir()
	t.Cleanup(func() { dhcpRuntimeDir = oldRuntime })
	state := filepath.Join(dhcpRuntimeDir, "netos-dhcp-wan0.address")
	if err := os.WriteFile(state, []byte("192.0.2.10/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "2: wan0 inet 192.0.2.10/24 scope global wan0\n", nil
	})
	s := NewWAN(runner)
	s.DHCPTimeout, s.DHCPPoll = 10*time.Millisecond, time.Millisecond
	if err := s.waitDHCP(context.Background(), "wan0", "DHCP"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("192.0.2.99/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.waitDHCP(context.Background(), "wan0", "DHCP"); err == nil || !strings.Contains(err.Error(), "не получил адрес") {
		t.Fatalf("stale lease state accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.DHCPTimeout = time.Second
	if err := s.waitDHCP(ctx, "wan0", "DHCP"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DHCP cancellation = %v", err)
	}
}

func TestWaitPPPoESuccessTimeoutAndCancellation(t *testing.T) {
	w := config.WAN{ID: "wan1", Name: "PPPoE"}
	success := NewWAN(netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "9: ppp-wan1 inet 10.0.0.2 peer 10.0.0.1/32 scope global ppp-wan1\n", nil
	}))
	success.PPPoETimeout, success.PPPoePoll = 10*time.Millisecond, time.Millisecond
	if err := success.waitPPPoE(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	failing := NewWAN(netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "", errors.New("missing")
	}))
	failing.PPPoETimeout, failing.PPPoePoll = 5*time.Millisecond, time.Millisecond
	if err := failing.waitPPPoE(context.Background(), w); err == nil || !strings.Contains(err.Error(), "не поднялся") {
		t.Fatalf("missing PPP session accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failing.PPPoETimeout = time.Second
	if err := failing.waitPPPoE(ctx, w); !errors.Is(err, context.Canceled) {
		t.Fatalf("PPPoE cancellation = %v", err)
	}
}

func TestUnderlayGatewayParsesExactViaAndReportsReadError(t *testing.T) {
	s := NewWAN(netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "default via 192.0.2.1 dev wan0 proto dhcp metric 100\n", nil
	}))
	if got, err := s.underlayGateway(context.Background(), "wan0"); err != nil || got != "192.0.2.1" {
		t.Fatalf("gateway = %q (%v)", got, err)
	}
	s.Runner = netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "", errors.New("route read failed")
	})
	if _, err := s.underlayGateway(context.Background(), "wan0"); err == nil || !strings.Contains(err.Error(), "route read failed") {
		t.Fatalf("route read failure hidden: %v", err)
	}
}

func TestConfigureChangesMACWhileDownAndRestoresRequestedState(t *testing.T) {
	newFakeNet(t, "eth-test")
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if command == "ip -o link show dev eth-test" {
			return "2: eth-test: <BROADCAST,UP> mtu 1500 link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n", nil
		}
		return "", nil
	})
	iface := config.Interface{ID: "eth", Name: "eth-test", Type: "physical", Enabled: true, MAC: "02:00:00:00:00:02"}
	if err := NewInterfaces(runner).configure(context.Background(), &config.Config{Interfaces: []config.Interface{iface}}, iface); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	down := strings.Index(joined, "ip link set eth-test down")
	change := strings.Index(joined, "ip link set eth-test address 02:00:00:00:00:02")
	up := strings.LastIndex(joined, "ip link set eth-test up")
	if down < 0 || change <= down || up <= change {
		t.Fatalf("unsafe MAC transition order:\n%s", joined)
	}
}

func TestConfigureDoesNotBounceLinkWhenMACAlreadyMatches(t *testing.T) {
	newFakeNet(t, "eth-test")
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if command == "ip -o link show dev eth-test" {
			return "2: eth-test: <BROADCAST,UP> mtu 1500 link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n", nil
		}
		return "", nil
	})
	iface := config.Interface{ID: "eth", Name: "eth-test", Type: "physical", Enabled: true, MAC: "02:00:00:00:00:02"}
	if err := NewInterfaces(runner).configure(context.Background(), &config.Config{Interfaces: []config.Interface{iface}}, iface); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "eth-test down") || strings.Contains(joined, "eth-test address") {
		t.Fatalf("unchanged MAC bounced the link:\n%s", joined)
	}
}

func TestInterfacesHealthUsesFinalWANLinkStateAndMTU(t *testing.T) {
	newFakeNet(t, "wan0")
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if name+" "+strings.Join(args, " ") == "ip -o link show dev wan0" {
			return "2: wan0: <BROADCAST,UP,LOWER_UP> mtu 1492 state UP link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n", nil
		}
		return "", nil
	})
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{
		ID: "if", Name: "wan0", Type: "physical", Enabled: false, MTU: 1500,
	}}
	cfg.WANs = []config.WAN{{
		ID: "wan", Name: "WAN", Interface: "if", Proto: "dhcp", Enabled: true, Metric: 100, MTU: 1492,
	}}
	if err := NewInterfaces(runner).Health(context.Background(), cfg); err != nil {
		t.Fatalf("final link state produced by WAN was rejected: %v", err)
	}

	cfg.WANs[0].MTU = 1480
	if err := NewInterfaces(runner).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("WAN MTU drift passed interface health: %v", err)
	}
}

func TestWANHealthAcceptsCompleteDHCPPPPoEAndL2TPStates(t *testing.T) {
	t.Run("dhcp", func(t *testing.T) {
		newFakeNet(t, "wan0")
		oldRuntime := dhcpRuntimeDir
		dhcpRuntimeDir = t.TempDir()
		t.Cleanup(func() { dhcpRuntimeDir = oldRuntime })
		if err := os.WriteFile(filepath.Join(dhcpRuntimeDir, "netos-dhcp-wan0.address"), []byte("192.0.2.2/24\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runner := healthyWANRunner(map[string]string{
			"ip -4 -o addr show dev wan0": "2: wan0 inet 192.0.2.2/24 scope global wan0\n",
			"ip -4 route show default":    "default via 192.0.2.1 dev wan0 proto dhcp metric 100\n",
		})
		s := NewWAN(runner)
		s.DHCPTimeout, s.DHCPPoll = 10*time.Millisecond, time.Millisecond
		cfg := config.Default()
		cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0", Type: "physical", Enabled: true}}
		cfg.WANs = []config.WAN{{ID: "dhcp", Name: "DHCP", Interface: "if", Proto: "dhcp", Enabled: true, Metric: 100}}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("pppoe", func(t *testing.T) {
		newFakeNet(t, "wan0")
		runner := healthyWANRunner(map[string]string{
			"ip -4 -o addr show dev ppp-ppp": "9: ppp-ppp inet 10.0.0.2 peer 10.0.0.1/32 scope global ppp-ppp\n",
			"ip -4 route show default":       "default dev ppp-ppp metric 200\n",
		})
		s := NewWAN(runner)
		s.PPPoETimeout, s.PPPoePoll = 10*time.Millisecond, time.Millisecond
		cfg := config.Default()
		cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0", Type: "physical", Enabled: true}}
		cfg.WANs = []config.WAN{{ID: "ppp", Name: "PPPoE", Interface: "if", Proto: "pppoe", Enabled: true, Metric: 200}}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("l2tp-static", func(t *testing.T) {
		newFakeNet(t, "wan0")
		runner := healthyWANRunner(map[string]string{
			"ip -4 -o addr show dev wan0":     "2: wan0 inet 192.0.2.2/24 scope global wan0\n",
			"ip -4 -o addr show dev ppp-l2tp": "10: ppp-l2tp inet 10.1.0.2 peer 10.1.0.1/32 scope global ppp-l2tp\n",
			"ip -4 route show default":        "default via 192.0.2.1 dev wan0 proto netos metric 310\ndefault dev ppp-l2tp metric 300\n",
			"ip -4 route show 203.0.113.7/32": "203.0.113.7 via 192.0.2.1 dev wan0 proto 201\n",
		})
		s := NewWAN(runner)
		s.OwnedLNSRoutePath = filepath.Join(t.TempDir(), "owned-lns.json")
		if err := s.writeOwnedLNSRoutes([]ownedLNSRoute{{Destination: "203.0.113.7/32", Gateway: "192.0.2.1", Interface: "wan0"}}); err != nil {
			t.Fatal(err)
		}
		s.PPPoETimeout, s.PPPoePoll = 10*time.Millisecond, time.Millisecond
		cfg := config.Default()
		cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0", Type: "physical", Enabled: true}}
		cfg.WANs = []config.WAN{{ID: "l2tp", Name: "L2TP", Interface: "if", Proto: "l2tp", Underlay: "static",
			Address: "192.0.2.2/24", Gateway: "192.0.2.1", Enabled: true, Metric: 300}}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWANHealthRejectsMissingOwnedLNSRoute(t *testing.T) {
	newFakeNet(t, "wan0")
	runner := healthyWANRunner(map[string]string{
		"ip -4 -o addr show dev wan0":     "2: wan0 inet 192.0.2.2/24 scope global wan0\n",
		"ip -4 -o addr show dev ppp-l2tp": "10: ppp-l2tp inet 10.1.0.2 peer 10.1.0.1/32 scope global ppp-l2tp\n",
		"ip -4 route show default":        "default dev ppp-l2tp metric 300\n",
	})
	s := NewWAN(runner)
	s.OwnedLNSRoutePath = filepath.Join(t.TempDir(), "owned-lns.json")
	if err := s.writeOwnedLNSRoutes([]ownedLNSRoute{{Destination: "203.0.113.7/32", Gateway: "192.0.2.1", Interface: "wan0"}}); err != nil {
		t.Fatal(err)
	}
	s.PPPoETimeout, s.PPPoePoll = 10*time.Millisecond, time.Millisecond
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "l2tp", Name: "L2TP", Interface: "if", Proto: "l2tp", Underlay: "static", Address: "192.0.2.2/24", Gateway: "192.0.2.1", Server: "203.0.113.7", Enabled: true, Metric: 300}}
	err := s.Health(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "маршрут L2TP") {
		t.Fatalf("missing LNS route passed health: %v", err)
	}
}

func TestWANHealthRejectsActiveButDisabledUnit(t *testing.T) {
	newFakeNet(t, "wan0")
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "active\n", nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "is-enabled" {
			return "disabled\n", errors.New("disabled")
		}
		return "", nil
	})
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if", Name: "wan0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "dhcp", Name: "DHCP", Interface: "if", Proto: "dhcp", Enabled: true, Metric: 100}}
	err := NewWAN(runner).Health(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "автозапуска") {
		t.Fatalf("active but disabled unit passed WAN health: %v", err)
	}
}

func healthyWANRunner(outputs map[string]string) netifaceRunnerFunc {
	return func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "active\n", nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "is-enabled" {
			return "enabled\n", nil
		}
		if output, ok := outputs[command]; ok {
			return output, nil
		}
		return "", nil
	}
}

func assertAction(t *testing.T, actions []apply.Action, kind, target string, disruptive bool) {
	t.Helper()
	action := findAction(actions, kind, target)
	if action == nil || action.Disruptive != disruptive {
		t.Fatalf("action %s %s disruptive=%v missing/mismatched in %#v", kind, target, disruptive, actions)
	}
}

func findAction(actions []apply.Action, kind, target string) *apply.Action {
	for i := range actions {
		if actions[i].Kind == kind && actions[i].Target == target {
			return &actions[i]
		}
	}
	return nil
}
