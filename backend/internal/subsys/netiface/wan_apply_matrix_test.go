package netiface

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type wanApplyMatrixRunner struct {
	active   map[string]bool
	commands []string
	failAt   string
}

type wanIdempotencyRunner struct {
	commands     []string
	active       map[string]bool
	enabled      map[string]bool
	linkUp       bool
	mtu          int
	addresses    map[string]bool
	defaultRoute string
	routes       map[string]string
}

func newWANIdempotencyRunner() *wanIdempotencyRunner {
	return &wanIdempotencyRunner{
		active: map[string]bool{}, enabled: map[string]bool{}, mtu: 1500,
		addresses: map[string]bool{}, routes: map[string]string{},
	}
}

func (r *wanIdempotencyRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if name == "systemctl" && len(args) > 0 {
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if r.active[unit] {
				return "active\n", nil
			}
			return "inactive\n", errors.New("inactive")
		case "is-enabled":
			if r.enabled[unit] {
				return "enabled\n", nil
			}
			return "disabled\n", errors.New("disabled")
		case "enable":
			r.enabled[unit] = true
			if len(args) > 1 && args[1] == "--now" {
				r.active[unit] = true
			}
		case "restart":
			r.active[unit] = true
		case "disable":
			r.active[unit], r.enabled[unit] = false, false
		}
		return "", nil
	}
	switch {
	case command == "ip -o link show dev eth-test":
		flags := "BROADCAST,LOWER_UP"
		if r.linkUp {
			flags = "BROADCAST,UP,LOWER_UP"
		}
		return fmt.Sprintf("2: eth-test: <%s> mtu %d state UP link/ether 02:00:00:00:00:02\n", flags, r.mtu), nil
	case command == "ip link set eth-test up":
		r.linkUp = true
	case strings.HasPrefix(command, "ip link set eth-test mtu "):
		r.mtu, _ = strconv.Atoi(args[len(args)-1])
	case command == "ip -4 -o addr show dev eth-test":
		var lines []string
		for address := range r.addresses {
			lines = append(lines, "2: eth-test inet "+address+" scope global eth-test")
		}
		return strings.Join(lines, "\n"), nil
	case len(args) >= 5 && name == "ip" && args[0] == "addr" && (args[1] == "replace" || args[1] == "add"):
		r.addresses[args[2]] = true
	case command == "ip -4 route show default":
		return r.defaultRoute, nil
	case strings.HasPrefix(command, "ip route replace default "):
		r.defaultRoute = "default via " + args[4] + " dev " + args[6] + " metric " + args[8] + " proto " + args[10] + "\n"
	case len(args) == 4 && name == "ip" && args[0] == "-4" && args[1] == "route" && args[2] == "show":
		return r.routes[args[3]], nil
	case len(args) >= 9 && name == "ip" && args[0] == "route" && args[1] == "replace":
		destination := args[2]
		r.routes[destination] = destination + " via " + args[4] + " dev " + args[6] + " proto " + args[8] + "\n"
	}
	return "", nil
}

func (r *wanIdempotencyRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *wanApplyMatrixRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failAt != "" && strings.Contains(command, r.failAt) {
		return "", errors.New("injected failure")
	}
	if name != "systemctl" || len(args) == 0 {
		return "", nil
	}
	unit := args[len(args)-1]
	switch args[0] {
	case "is-active":
		if r.active[unit] {
			return "active\n", nil
		}
		return "inactive\n", errors.New("inactive")
	case "enable":
		if len(args) > 1 && args[1] == "--now" {
			r.active[unit] = true
		}
	case "restart":
		r.active[unit] = true
	case "disable":
		r.active[unit] = false
	}
	return "", nil
}

func TestWANApplyPreflightAndProvisionalOwnershipOrdering(t *testing.T) {
	setup := func(t *testing.T, link bool, failAt string) (*WAN, *wanApplyMatrixRunner, *config.Config) {
		t.Helper()
		if link {
			newFakeNet(t, "eth-test")
		} else {
			newFakeNet(t)
		}
		root := t.TempDir()
		oldScripts, oldRuntime, oldUnits, oldConfs := dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir
		dhcpScriptDir = filepath.Join(root, "state")
		dhcpRuntimeDir = filepath.Join(root, "run")
		systemdUnitDir = filepath.Join(root, "units")
		pppoeConfDir = dhcpScriptDir
		t.Cleanup(func() {
			dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir = oldScripts, oldRuntime, oldUnits, oldConfs
		})
		for _, dir := range []string{dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		runner := &wanApplyMatrixRunner{active: map[string]bool{}, failAt: failAt}
		s := NewWAN(runner)
		s.OwnedAddressPath = filepath.Join(root, "owned-addresses.json")
		s.OwnedRoutePath = filepath.Join(root, "owned-routes.json")
		s.OwnedLNSRoutePath = filepath.Join(root, "owned-lns-routes.json")
		cfg := config.Default()
		cfg.Interfaces = []config.Interface{{ID: "physical", Name: "eth-test", Type: "physical", Enabled: true}}
		cfg.WANs = []config.WAN{{ID: "static", Name: "Static", Interface: "physical", Enabled: true, Proto: "static",
			Address: "192.0.2.2/24", Gateway: "192.0.2.1", Metric: 10}}
		return s, runner, cfg
	}

	t.Run("missing link fails before any mutation or ownership", func(t *testing.T) {
		s, runner, cfg := setup(t, false, "")
		if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "отсутствует") {
			t.Fatalf("missing-link error=%v", err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("preflight mutated system: %v", runner.commands)
		}
		for _, path := range []string{s.OwnedAddressPath, s.OwnedRoutePath, s.OwnedLNSRoutePath} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("preflight created ownership %s: %v", path, err)
			}
		}
	})

	t.Run("link failure does not claim unattempted address", func(t *testing.T) {
		s, _, cfg := setup(t, true, "ip link set eth-test up")
		if err := s.Apply(context.Background(), cfg); err == nil {
			t.Fatal("link failure was ignored")
		}
		if _, err := os.Stat(s.OwnedAddressPath); !os.IsNotExist(err) {
			t.Fatalf("unattempted address was claimed: %v", err)
		}
	})

	t.Run("address failure records only attempted address", func(t *testing.T) {
		s, _, cfg := setup(t, true, "ip addr replace")
		if err := s.Apply(context.Background(), cfg); err == nil {
			t.Fatal("address failure was ignored")
		}
		addresses, err := s.readOwnedWANAddresses()
		if err != nil || len(addresses) != 1 || addresses[0].Address != cfg.WANs[0].Address {
			t.Fatalf("attempted address ownership=%#v err=%v", addresses, err)
		}
		if _, err := os.Stat(s.OwnedRoutePath); !os.IsNotExist(err) {
			t.Fatalf("unattempted route was claimed: %v", err)
		}
	})

	t.Run("route failure keeps both completed and attempted ownership", func(t *testing.T) {
		s, _, cfg := setup(t, true, "ip route replace default")
		if err := s.Apply(context.Background(), cfg); err == nil {
			t.Fatal("route failure was ignored")
		}
		addresses, addressErr := s.readOwnedWANAddresses()
		routes, routeErr := s.readOwnedWANRoutes()
		if addressErr != nil || routeErr != nil || len(addresses) != 1 || len(routes) != 1 {
			t.Fatalf("provisional ownership addresses=%#v routes=%#v errors=%v/%v", addresses, routes, addressErr, routeErr)
		}
	})
}

func (r *wanApplyMatrixRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestWANApplyExecutesEverySupportedProtocolEndToEnd(t *testing.T) {
	tests := []struct {
		name string
		wan  config.WAN
		want []string
	}{
		{
			name: "static",
			wan: config.WAN{ID: "static", Name: "Static", Enabled: true, Proto: "static",
				Address: "192.0.2.2/24", Gateway: "192.0.2.1", Metric: 10, MTU: 1492},
			want: []string{
				"ip link set eth-test up", "ip link set eth-test mtu 1492",
				"ip addr replace 192.0.2.2/24 dev eth-test",
				"ip route replace default via 192.0.2.1 dev eth-test metric 10 proto 201",
			},
		},
		{
			name: "dhcp",
			wan:  config.WAN{ID: "dhcp", Name: "DHCP", Enabled: true, Proto: "dhcp", Metric: 20},
			want: []string{"ip link set eth-test up", "systemctl enable --now netos-dhcp-eth-test.service"},
		},
		{
			name: "pppoe",
			wan: config.WAN{ID: "pppoe", Name: "PPPoE", Enabled: true, Proto: "pppoe",
				Username: "subscriber", Password: "secret", Metric: 30},
			want: []string{"ip link set eth-test up", "systemctl restart netos-pppoe-pppoe.service"},
		},
		{
			name: "l2tp-static-underlay",
			wan: config.WAN{ID: "l2tp", Name: "L2TP", Enabled: true, Proto: "l2tp", Underlay: "static",
				Address: "198.51.100.2/24", Gateway: "198.51.100.1", Server: "203.0.113.7",
				Username: "subscriber", Password: "secret", Metric: 40},
			want: []string{
				"ip link set eth-test up",
				"ip addr replace 198.51.100.2/24 dev eth-test",
				"ip route replace default via 198.51.100.1 dev eth-test metric 50 proto 201",
				"ip route replace 203.0.113.7/32 via 198.51.100.1 dev eth-test proto 201",
				"systemctl restart netos-l2tp-l2tp.service",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newFakeNet(t, "eth-test")
			root := t.TempDir()
			oldScripts, oldRuntime, oldUnits, oldConfs := dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir
			dhcpScriptDir = filepath.Join(root, "state")
			dhcpRuntimeDir = filepath.Join(root, "run")
			systemdUnitDir = filepath.Join(root, "units")
			pppoeConfDir = dhcpScriptDir
			t.Cleanup(func() {
				dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir = oldScripts, oldRuntime, oldUnits, oldConfs
			})
			for _, dir := range []string{dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			runner := &wanApplyMatrixRunner{active: map[string]bool{}}
			s := NewWAN(runner)
			s.OwnedAddressPath = filepath.Join(root, "owned-addresses.json")
			s.OwnedRoutePath = filepath.Join(root, "owned-routes.json")
			s.OwnedLNSRoutePath = filepath.Join(root, "owned-lns-routes.json")
			cfg := config.Default()
			cfg.Interfaces = []config.Interface{{ID: "physical", Name: "eth-test", Type: "physical", Enabled: true}}
			tc.wan.Interface = "physical"
			cfg.WANs = []config.WAN{tc.wan}
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			commands := strings.Join(runner.commands, "\n")
			for _, want := range tc.want {
				if !strings.Contains(commands, want) {
					t.Fatalf("missing command %q:\n%s", want, commands)
				}
			}
			for _, path := range []string{s.OwnedAddressPath, s.OwnedRoutePath, s.OwnedLNSRoutePath} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("ownership %s was not persisted: %v", path, err)
				}
			}
		})
	}
}

func TestWANApplyIsIdempotentForEverySupportedProtocol(t *testing.T) {
	tests := []struct {
		name string
		wan  config.WAN
	}{
		{"static", config.WAN{ID: "static", Name: "Static", Enabled: true, Proto: "static", Address: "192.0.2.2/24", Gateway: "192.0.2.1", Metric: 10, MTU: 1492}},
		{"dhcp", config.WAN{ID: "dhcp", Name: "DHCP", Enabled: true, Proto: "dhcp", Metric: 20}},
		{"pppoe", config.WAN{ID: "pppoe", Name: "PPPoE", Enabled: true, Proto: "pppoe", Username: "subscriber", Password: "secret", Metric: 30}},
		{"l2tp", config.WAN{ID: "l2tp", Name: "L2TP", Enabled: true, Proto: "l2tp", Underlay: "static", Address: "198.51.100.2/24", Gateway: "198.51.100.1", Server: "203.0.113.7", Username: "subscriber", Password: "secret", Metric: 40}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newFakeNet(t, "eth-test")
			root := t.TempDir()
			oldScripts, oldRuntime, oldUnits, oldConfs := dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir
			dhcpScriptDir = filepath.Join(root, "state")
			dhcpRuntimeDir = filepath.Join(root, "run")
			systemdUnitDir = filepath.Join(root, "units")
			pppoeConfDir = dhcpScriptDir
			t.Cleanup(func() {
				dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir, pppoeConfDir = oldScripts, oldRuntime, oldUnits, oldConfs
			})
			for _, dir := range []string{dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			runner := newWANIdempotencyRunner()
			s := NewWAN(runner)
			s.OwnedAddressPath = filepath.Join(root, "owned-addresses.json")
			s.OwnedRoutePath = filepath.Join(root, "owned-routes.json")
			s.OwnedLNSRoutePath = filepath.Join(root, "owned-lns-routes.json")
			cfg := config.Default()
			cfg.Interfaces = []config.Interface{{ID: "physical", Name: "eth-test", Type: "physical", Enabled: true}}
			tc.wan.Interface = "physical"
			cfg.WANs = []config.WAN{tc.wan}
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			mtimes := map[string]time.Time{}
			if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				info, err := entry.Info()
				if err == nil && info.Mode().IsRegular() {
					mtimes[path] = info.ModTime()
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}

			time.Sleep(25 * time.Millisecond)
			runner.commands = nil
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " daemon-reload") || strings.Contains(command, " restart ") ||
					strings.Contains(command, " enable ") || strings.Contains(command, " disable ") ||
					strings.HasPrefix(command, "ip link set ") || strings.HasPrefix(command, "ip addr ") ||
					strings.HasPrefix(command, "ip route replace ") || strings.HasPrefix(command, "ip -4 route del ") {
					t.Fatalf("second Apply mutated runtime: %s\nall commands: %v", command, runner.commands)
				}
			}
			for path, before := range mtimes {
				info, err := os.Stat(path)
				if err != nil || !before.Equal(info.ModTime()) {
					t.Fatalf("second Apply replaced %s: before=%v after=%v err=%v", path, before, info.ModTime(), err)
				}
			}
		})
	}
}

func TestNetworksApplyIsIdempotentAtRuntimeAndOnDisk(t *testing.T) {
	newFakeNet(t, "eth-test")
	runner := newWANIdempotencyRunner()
	root := t.TempDir()
	s := NewNetworks(runner)
	s.OwnedAddressPath = filepath.Join(root, "owned-network-addresses.json")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "eth-test", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "segment", Name: "LAN", Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(s.OwnedAddressPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "ip addr ") || strings.HasPrefix(command, "ip link set ") {
			t.Fatalf("second Networks.Apply mutated runtime: %s; all=%v", command, runner.commands)
		}
	}
	after, err := os.Stat(s.OwnedAddressPath)
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("second Networks.Apply replaced ownership: before=%v after=%v err=%v", before.ModTime(), after.ModTime(), err)
	}
}

func TestDHCPApplyRepairsDisabledAutostartWithoutRestartingActiveLease(t *testing.T) {
	newFakeNet(t, "eth-test")
	root := t.TempDir()
	oldScripts, oldRuntime, oldUnits := dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir
	dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir = filepath.Join(root, "state"), filepath.Join(root, "run"), filepath.Join(root, "units")
	t.Cleanup(func() { dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir = oldScripts, oldRuntime, oldUnits })
	for _, dir := range []string{dhcpScriptDir, dhcpRuntimeDir, systemdUnitDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runner := newWANIdempotencyRunner()
	s := NewWAN(runner)
	s.OwnedAddressPath = filepath.Join(root, "owned-addresses.json")
	s.OwnedRoutePath = filepath.Join(root, "owned-routes.json")
	s.OwnedLNSRoutePath = filepath.Join(root, "owned-lns-routes.json")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "physical", Name: "eth-test", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "dhcp", Name: "DHCP", Interface: "physical", Enabled: true, Proto: "dhcp", Metric: 20}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	unit := "netos-dhcp-eth-test.service"
	runner.enabled[unit] = false
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "systemctl enable "+unit) || strings.Contains(joined, "systemctl restart "+unit) {
		t.Fatalf("active disabled DHCP repair commands:\n%s", joined)
	}
}
