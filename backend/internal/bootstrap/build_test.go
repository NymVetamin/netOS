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
	for _, name := range []string{"lo", "eth0", "eth1", "eth2", "tun0"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"eth0", "eth1", "eth2"} {
		if err := os.WriteFile(filepath.Join(root, name, "device"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := detectRunner{
		routes: "default via 192.0.2.1 dev eth0 proto dhcp metric 10\n" +
			"default via 198.51.100.1 dev eth1 proto static metric 500\n",
		addrs: map[string]string{
			"eth0": "2: eth0 inet 192.0.2.10/24 scope global eth0\n",
			"eth1": "3: eth1 inet 198.51.100.10/24 scope global eth1\n",
			"eth2": "",
		},
	}
	d, err := Detect(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if d.WANInterface != "eth0" || d.WANGateway != "192.0.2.1" || d.WANAddress != "192.0.2.10/24" {
		t.Fatalf("preferred WAN=%+v", d)
	}
	if !reflect.DeepEqual(d.AllInterfaces, []string{"eth0", "eth1", "eth2"}) || !reflect.DeepEqual(d.LANCandidates, []string{"eth2"}) {
		t.Fatalf("interfaces=%v LAN=%v", d.AllInterfaces, d.LANCandidates)
	}
	if !reflect.DeepEqual(d.OccupiedCIDRs, []string{"192.0.2.0/24", "198.51.100.0/24"}) || d.ManagementCIDR != "192.0.2.0/24" {
		t.Fatalf("occupied=%v management=%s", d.OccupiedCIDRs, d.ManagementCIDR)
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

func (r addressRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestBuildInitialWithoutInterfacesKeepsSafeDefaults(t *testing.T) {
	cfg := BuildInitial(&Detected{})
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
			cfg := BuildInitial(&Detected{WANInterface: "eth0", WANAddress: tc.address, WANGateway: tc.gateway})
			if len(cfg.Interfaces) != 1 || cfg.Interfaces[0].Name != "eth0" || len(cfg.WANs) != 1 {
				t.Fatalf("unexpected WAN objects: interfaces=%v wans=%v", cfg.Interfaces, cfg.WANs)
			}
			wan := cfg.WANs[0]
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
	cfg := BuildInitial(d)
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
	got := pickFreeSubnet(d)
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
