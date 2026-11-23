package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type addressRunner struct {
	output string
	err    error
}

type detectRunner struct {
	routes string
	addrs  map[string]string
	errors map[string]error
}

func (r detectRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, "route show default") {
		return r.routes, nil
	}
	if strings.Contains(command, "addr show dev") && len(args) > 0 {
		iface := args[len(args)-1]
		if err := r.errors[iface]; err != nil {
			return "", err
		}
		return r.addrs[iface], nil
	}
	return "", fmt.Errorf("unexpected command %s", command)
}

func (r detectRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestDetectUsesPreferredDefaultAndAllPhysicalSubnets(t *testing.T) {
	root := t.TempDir()
	oldRoot := sysClassNet
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = oldRoot })
	for _, name := range []string{"lo", "eth0", "eth1", "eth2", "tun0", "wlan0"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"eth0", "eth1", "eth2", "wlan0"} {
		if err := os.WriteFile(filepath.Join(root, name, "device"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "wlan0", "wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := detectRunner{
		routes: "default via 192.0.2.1 dev eth0 proto dhcp metric 10\n" +
			"default via 198.51.100.1 dev eth1 proto static metric 500\n",
		addrs: map[string]string{
			"eth0":  "2: eth0 inet 192.0.2.10/24 scope global eth0\n",
			"eth1":  "3: eth1 inet 198.51.100.10/24 scope global eth1\n",
			"eth2":  "",
			"wlan0": "",
		},
	}
	d, err := Detect(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if d.WANInterface != "eth0" || d.WANGateway != "192.0.2.1" || d.WANAddress != "192.0.2.10/24" {
		t.Fatalf("preferred WAN=%+v", d)
	}
	if !reflect.DeepEqual(d.AllInterfaces, []string{"eth0", "eth1", "eth2", "wlan0"}) || !reflect.DeepEqual(d.LANCandidates, []string{"eth2"}) {
		t.Fatalf("interfaces=%v LAN=%v", d.AllInterfaces, d.LANCandidates)
	}
	if !reflect.DeepEqual(d.OccupiedCIDRs, []string{"192.0.2.0/24", "198.51.100.0/24"}) || d.ManagementCIDR != "192.0.2.0/24" {
		t.Fatalf("occupied=%v management=%s", d.OccupiedCIDRs, d.ManagementCIDR)
	}
}

func TestDetectRefusesExistingBridgeOnlyOnPreferredRoute(t *testing.T) {
	old := sysClassNet
	sysClassNet = t.TempDir()
	t.Cleanup(func() { sysClassNet = old })
	if err := os.MkdirAll(filepath.Join(sysClassNet, "brwan", "bridge"), 0755); err != nil {
		t.Fatal(err)
	}
	const bridge = "default via 192.0.2.1 dev brwan"
	const port = "default via 198.51.100.1 dev eth0"
	for attempt := 0; attempt < 2; attempt++ {
		d, err := Detect(context.Background(), detectRunner{routes: bridge + "\n" + port})
		if d != nil || err == nil || !strings.Contains(err.Error(), "мост brwan") {
			t.Fatalf("bridge bootstrap returned %+v, %v", d, err)
		}
	}
	d, err := Detect(context.Background(), detectRunner{routes: port + "\n" + bridge})
	if err != nil || d.WANInterface != "eth0" {
		t.Fatalf("physical uplink returned %+v, %v", d, err)
	}
	const bridgeHop = "nexthop via 192.0.2.1 dev brwan weight 1"
	const portHop = "nexthop via 198.51.100.1 dev eth0 weight 1"
	for _, route := range []string{bridgeHop + " " + portHop, portHop + " " + bridgeHop} {
		if _, err := Detect(context.Background(), detectRunner{routes: "default " + route}); err == nil || !strings.Contains(err.Error(), "мост brwan") {
			t.Fatalf("multipath default %q: %v", route, err)
		}
	}
	d, err = Detect(context.Background(), detectRunner{routes: "default " + portHop + " nexthop dev eth1 weight 1"})
	if err != nil || d.WANInterface != "eth1" || d.WANGateway != "" {
		t.Fatalf("device-only nexthop returned %+v, %v", d, err)
	}
}

func TestDetectFailsWithoutSysfsAndToleratesRouteAddressFailures(t *testing.T) {
	oldRoot := sysClassNet
	sysClassNet = filepath.Join(t.TempDir(), "missing")
	if _, err := Detect(context.Background(), detectRunner{}); err == nil {
		t.Fatal("missing sysfs root was accepted")
	}
	root := t.TempDir()
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = oldRoot })
	if err := os.MkdirAll(filepath.Join(root, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "eth0", "device"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Detect(context.Background(), detectRunner{
		routes: "unparseable default line\ndefault dev eth0 metric 10\n",
		errors: map[string]error{"eth0": errors.New("address read failed")},
	})
	if err != nil || d.WANInterface != "eth0" || d.WANGateway != "" || len(d.LANCandidates) != 0 {
		t.Fatalf("partial detect=%+v err=%v", d, err)
	}
}

func (r addressRunner) Run(context.Context, string, ...string) (string, error) {
	return r.output, r.err
}

func TestDetectKeepsUnnumberedWANOutOfLAN(t *testing.T) {
	old := sysClassNet
	sysClassNet = t.TempDir()
	t.Cleanup(func() { sysClassNet = old })
	for _, name := range []string{"eth0", "eth1"} {
		if err := os.MkdirAll(filepath.Join(sysClassNet, name, "device"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	d, err := Detect(context.Background(), detectRunner{routes: "default dev eth0 scope link"})
	if err != nil {
		t.Fatal(err)
	}
	if d.WANInterface != "eth0" || !reflect.DeepEqual(d.LANCandidates, []string{"eth1"}) {
		t.Fatalf("unexpected port assignment: %+v", d)
	}
	cfg, err := BuildInitial(d)
	if err != nil {
		t.Fatal(err)
	}
	if result := cfg.Validate(); result.HasErrors() || cfg.WANs[0].Proto != "dhcp" {
		t.Fatalf("initial configuration: %v, WANs %v", result.Problems, cfg.WANs)
	}
}

func (r addressRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestInitialLANSkipsExistingBridgePort(t *testing.T) {
	old := sysClassNet
	sysClassNet = t.TempDir()
	t.Cleanup(func() { sysClassNet = old })
	for _, path := range []string{"wan/device", "eth1/device", "eth1/brport"} {
		if err := os.MkdirAll(filepath.Join(sysClassNet, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string) {
		t.Helper()
		d, err := Detect(context.Background(), detectRunner{routes: "default dev wan"})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := BuildInitial(d)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Validate().HasErrors() || len(cfg.WANs) != 1 || cfg.WANs[0].Interface != "if-wan" {
			t.Fatalf("invalid startup configuration: %+v", cfg.WANs)
		}
		lan := ""
		for _, iface := range cfg.Interfaces {
			if iface.ID == "if-lan" {
				lan = iface.Name
			}
		}
		if lan != want || (len(cfg.Networks) > 0) != (want != "") {
			t.Fatalf("candidates %v, LAN %q, want %q", d.LANCandidates, lan, want)
		}
	}
	check("")
	if err := os.MkdirAll(filepath.Join(sysClassNet, "eth2", "device"), 0755); err != nil {
		t.Fatal(err)
	}
	check("eth2")
	if err := os.Remove(filepath.Join(sysClassNet, "eth1", "brport")); err != nil {
		t.Fatal(err)
	}
	check("eth1")
}

func TestBuildInitialWithoutInterfacesKeepsSafeDefaults(t *testing.T) {
	cfg, err := BuildInitial(&Detected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Interfaces) != 0 || len(cfg.WANs) != 0 || len(cfg.Networks) != 0 {
		t.Fatalf("empty detection created network objects: interfaces=%v wans=%v networks=%v",
			cfg.Interfaces, cfg.WANs, cfg.Networks)
	}
	if !cfg.Firewall.Enabled || cfg.DHCP.Enabled || cfg.DNS.Enabled {
		t.Fatalf("unsafe initial service defaults: firewall=%v dhcp=%v dns=%v",
			cfg.Firewall.Enabled, cfg.DHCP.Enabled, cfg.DNS.Enabled)
	}
}

func TestBuildInitialCreatesDHCPOrStaticWAN(t *testing.T) {
	for _, tc := range []struct {
		name, address, gateway, wantProto string
	}{
		{name: "dhcp", wantProto: "dhcp"},
		{name: "static", address: "192.0.2.5/24", gateway: "192.0.2.1", wantProto: "static"},
		{name: "incomplete remains dhcp", address: "192.0.2.5/24", wantProto: "dhcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := BuildInitial(&Detected{WANInterface: "eth0", WANAddress: tc.address, WANGateway: tc.gateway})
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Interfaces) != 1 || cfg.Interfaces[0].Name != "eth0" || len(cfg.WANs) != 1 {
				t.Fatalf("unexpected WAN objects: interfaces=%v wans=%v", cfg.Interfaces, cfg.WANs)
			}
			if len(cfg.Networks) != 0 {
				t.Fatalf("unexpected LAN without a free interface: %#v", cfg.Networks)
			}
			wan := cfg.WANs[0]
			if wan.Index != 1 {
				t.Fatalf("WAN index = %d, want 1", wan.Index)
			}
			if wan.Proto != tc.wantProto {
				t.Fatalf("WAN proto = %q, want %q", wan.Proto, tc.wantProto)
			}
			if tc.wantProto == "static" && (wan.Address != tc.address || wan.Gateway != tc.gateway) {
				t.Fatalf("static WAN lost address/gateway: %#v", wan)
			}
			if len(cfg.Firewall.NAT) != 1 || cfg.Firewall.NAT[0].Interface != "eth0" {
				t.Fatalf("WAN NAT not created: %#v", cfg.Firewall.NAT)
			}
		})
	}
}

func TestBuildInitialCreatesDisabledLANPoolAndAvoidsAllOccupiedSubnets(t *testing.T) {
	d := &Detected{
		WANInterface:   "eth0",
		WANAddress:     "203.0.113.5/24",
		WANGateway:     "203.0.113.1",
		LANCandidates:  []string{"eth1", "eth2"},
		ManagementCIDR: "203.0.113.0/24",
		OccupiedCIDRs: []string{
			"192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24",
		},
	}
	cfg, err := BuildInitial(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Networks) != 1 || cfg.Networks[0].RouterAddress != "192.168.40.1/24" {
		t.Fatalf("LAN did not avoid occupied subnets: %#v", cfg.Networks)
	}
	lan := cfg.Networks[0]
	if lan.DHCPPool.Enabled || lan.DHCPPool.Start != "192.168.40.100" || lan.DHCPPool.End != "192.168.40.200" {
		t.Fatalf("unexpected initial DHCP pool: %#v", lan.DHCPPool)
	}
	if len(cfg.Interfaces) != 3 || cfg.Interfaces[1].Name != "eth1" || cfg.Interfaces[2].Name != "br-lan" ||
		!reflect.DeepEqual(cfg.Interfaces[2].Members, []string{"if-lan"}) {
		t.Fatalf("unexpected LAN interface graph: %#v", cfg.Interfaces)
	}
}

func TestPickFreeSubnetUsesFallbackWhenPrivateCandidatesAreOccupied(t *testing.T) {
	d := &Detected{OccupiedCIDRs: []string{
		"192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24", "192.168.40.0/24", "192.168.50.0/24",
	}}
	got, err := pickFreeSubnet(d)
	if err != nil {
		t.Fatal(err)
	}
	if got.routerAddr != "10.77.0.1/24" || got.poolStart != "10.77.0.100" || got.poolEnd != "10.77.0.200" {
		t.Fatalf("fallback subnet = %#v", got)
	}
}

func TestAddressesOfParsesAllIPv4AddressesAndPropagatesFailure(t *testing.T) {
	out := "2: eth0 inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\n" +
		"2: eth0 inet 198.51.100.8/32 scope global secondary eth0\n"
	got, err := addressesOf(context.Background(), addressRunner{output: out}, "eth0")
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.5/24", "198.51.100.8/32"}) {
		t.Fatalf("addressesOf() = %v, %v", got, err)
	}
	wantErr := errors.New("ip failed")
	if _, err := addressesOf(context.Background(), addressRunner{err: wantErr}, "eth0"); !errors.Is(err, wantErr) {
		t.Fatalf("addressesOf() error = %v", err)
	}
}

func TestInitialLANPrefixOverlap(t *testing.T) {
	for _, tc := range []struct{ occupied, management, want string }{
		{"192.168.0.0/16", "", "10.77.0.1/24"},
		{"", "192.168.10.128/25", "192.168.20.1/24"},
		{"192.168.9.255/32", "", "192.168.10.1/24"},
		{"10.77.0.99/32", "192.168.0.0/16", ""},
	} {
		d := &Detected{OccupiedCIDRs: []string{tc.occupied}, ManagementCIDR: tc.management, LANCandidates: []string{"eth1"}}
		for range 2 {
			cfg, err := BuildInitial(d)
			if tc.want == "" {
				if err == nil || cfg != nil {
					t.Fatalf("occupied fallback: cfg=%v err=%v", cfg, err)
				}
				continue
			}
			if err != nil || len(cfg.Networks) != 1 || cfg.Networks[0].RouterAddress != tc.want {
				t.Fatalf("%+v: cfg=%v err=%v", tc, cfg, err)
			}
		}
	}
}
