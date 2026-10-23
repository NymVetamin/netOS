package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

type confirmationRunner struct {
	*firewallRunner
	rules, rpf, route string
	routeErr          error
	queries           int
	neighbours        string
}

func (r *confirmationRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "sysctl" {
		return r.rpf, nil
	}
	if name == "ip" && strings.Join(args, " ") == "-4 rule show" {
		return r.rules, nil
	}
	if name == "ip" && len(args) > 2 && args[2] == "neigh" {
		return r.neighbours, nil
	}
	if name == "ip" && len(args) > 3 && args[1] == "-j" {
		r.queries++
		return r.route, r.routeErr
	}
	return r.firewallRunner.Run(ctx, name, args...)
}

func TestClientPolicyConfirmationRequiresProvenManagementRoute(t *testing.T) {
	for _, mode := range []string{"safe", "unknown peer", "loopback", "outside LAN", "wrong local", "strict rpf", "bad rpf", "missing local rule", "interface rule", "blackhole", "route failure", "invalid route", "missing device", "mixed filter", "live drift"} {
		t.Run(mode, func(t *testing.T) {
			old, _ := configuredFirewall(t)
			old.Channels = []config.Channel{{ID: "direct", Type: "direct", Enabled: true}, {ID: "vpn", Type: "wireguard", Index: 1, Enabled: true}}
			old.Clients = []config.Client{{ID: "c", MAC: "02:00:00:00:00:02", Channel: "direct"}}
			next := *old
			next.Clients = append([]config.Client(nil), old.Clients...)
			next.Clients[0].Channel = "vpn"
			rs, err := Build(old)
			if err != nil {
				t.Fatal(err)
			}
			r := &confirmationRunner{firewallRunner: cleanFirewallRunner(rs), rules: "0: from all lookup local\n32766: from all lookup main\n", rpf: "2\n2\n", route: `[{"dst":"192.0.2.2","dev":"lan0"}]`}
			remote, local := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1")
			switch mode {
			case "unknown peer":
				remote = netip.Addr{}
			case "loopback":
				remote = netip.MustParseAddr("127.0.0.1")
			case "outside LAN":
				remote = netip.MustParseAddr("198.51.100.2")
			case "wrong local":
				local = netip.MustParseAddr("192.0.2.3")
			case "strict rpf":
				r.rpf = "2\n1\n"
			case "bad rpf":
				r.rpf = "2"
			case "missing local rule":
				r.rules = "32766: from all lookup main\n"
			case "interface rule":
				r.rules += "40000: from all iif lan0 lookup 5000\n"
			case "blackhole":
				r.route = `[{"type":"blackhole","dev":"lan0"}]`
			case "route failure":
				r.routeErr = errors.New("unreachable")
			case "invalid route":
				r.route = "invalid"
			case "missing device":
				r.route = `[{}]`
			case "mixed filter":
				next.Firewall.OutputPolicy = "drop"
			case "live drift":
				r.outputs["iptables-save"] = ""
			}
			ctx := apply.WithManagementConnection(context.Background(), remote, local)
			actions, err := New(r, t.TempDir()).PlanContext(ctx, old, &next)
			if err != nil {
				t.Fatal(err)
			}
			for i := range actions {
				actions[i].Subsystem = "firewall"
			}
			if got := !apply.NeedsConfirmation(actions); got != (mode == "safe") {
				t.Fatalf("safe=%v mode=%s actions=%+v", got, mode, actions)
			}
			if mode == "safe" && r.queries != 2 {
				t.Fatalf("must check direct and selected exit: %d", r.queries)
			}
		})
	}
}

func TestClientRoutingAllowlistPreservesOtherChanges(t *testing.T) {
	old, _ := configuredFirewall(t)
	old.DNS.Enabled = true
	old.Channels = []config.Channel{{ID: "direct", Type: "direct", Enabled: true}, {ID: "vpn", Type: "wireguard", Index: 1, Enabled: true}}
	for _, mode := range []string{"client", "segment", "policy", "blocked", "dns intercept", "NAT", "IPv6"} {
		t.Run(mode, func(t *testing.T) {
			next := *old
			next.Networks = append([]config.Network(nil), old.Networks...)
			safe := true
			switch mode {
			case "client":
				next.Clients = []config.Client{{ID: "c", MAC: "02:00:00:00:00:02", Channel: "vpn"}}
			case "segment":
				next.Networks[0].DefaultChannel = "vpn"
			case "policy":
				next.Policies = []config.Policy{{ID: "p", Enabled: true, Channel: "vpn", SrcIP: "192.0.2.2"}}
			case "blocked":
				next.Clients = []config.Client{{ID: "c", MAC: "02:00:00:00:00:02", Blocked: true}}
				safe = false
			case "dns intercept":
				next.DNS.ForceLocal = !old.DNS.ForceLocal
				safe = false
			case "NAT":
				next.Firewall.NAT = []config.NATRule{{ID: "n", Enabled: true, Direction: "source", Interface: "eth0"}}
				safe = false
			case "IPv6":
				next.IPv6.Mode = "passthrough"
				safe = false
			}
			if got := clientRoutingOnly(old, &next); got != safe {
				t.Fatalf("allowlist %s=%v expected %v", mode, got, safe)
			}
		})
	}
}

func TestKernelVPNRoutingConfirmation(t *testing.T) {
	for _, vpnType := range []string{"wireguard", "ocserv"} {
		for _, mode := range []string{"default", "peer", "policy", "unknown management", "blackhole", "mixed port", "live drift"} {
			t.Run(vpnType+"/"+mode, func(t *testing.T) {
				old, _ := configuredFirewall(t)
				old.Channels = []config.Channel{{ID: "direct", Type: "direct", Enabled: true}, {ID: "vpn", Type: "wireguard", Index: 1, Enabled: true}}
				old.VPNServers = []config.VPNServer{{ID: "wg", Type: "wireguard", Index: 2, Enabled: true, Subnet: "10.9.0.1/24", Port: 51820, DefaultChannel: "direct", Peers: []config.VPNPeer{{ID: "peer", Enabled: true, Address: "10.9.0.2"}}}}
				old.VPNServers[0].Type = vpnType
				next := *old
				next.VPNServers = append([]config.VPNServer(nil), old.VPNServers...)
				next.VPNServers[0].Peers = append([]config.VPNPeer(nil), old.VPNServers[0].Peers...)
				next.VPNServers[0].DefaultChannel = "vpn"
				if mode == "peer" {
					next.VPNServers[0].DefaultChannel = "direct"
					next.VPNServers[0].Peers[0].Channel = "vpn"
				}
				if mode == "policy" {
					next.VPNServers[0].DefaultChannel = "direct"
					next.Policies = []config.Policy{{ID: "p", Enabled: true, Channel: "vpn", VPNServer: "wg", VPNPeer: "peer"}}
				}
				rs, err := Build(old)
				if err != nil {
					t.Fatal(err)
				}
				r := &confirmationRunner{firewallRunner: cleanFirewallRunner(rs), rules: "0: from all lookup local\n32766: from all lookup main\n", rpf: "2\n2\n", route: `[{"dev":"lan0"}]`}
				ctx := apply.WithManagementConnection(context.Background(), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
				switch mode {
				case "unknown management":
					ctx = context.Background()
				case "blackhole":
					r.route = `[{"type":"blackhole"}]`
				case "mixed port":
					next.VPNServers[0].Port++
				case "live drift":
					r.outputs["iptables-save"] = ""
				}
				actions, err := New(r, t.TempDir()).PlanContext(ctx, old, &next)
				if err != nil || len(actions) == 0 {
					t.Fatalf("plan: %v %v", actions, err)
				}
				for i := range actions {
					actions[i].Subsystem = "firewall"
				}
				if mode == "mixed port" {
					// The VPN subsystem owns the listening port and marks its change disruptive.
					actions = append(actions, apply.Action{Subsystem: "vpn-servers", Disruptive: true})
				}
				safe := mode == "default" || mode == "peer" || mode == "policy"
				if !apply.NeedsConfirmation(actions) != safe {
					t.Fatalf("safe=%v: %v", safe, actions)
				}
				if safe && r.queries != 2 {
					t.Fatalf("selected VPN mark not checked: %d", r.queries)
				}
				if old.VPNServers[0].DefaultChannel != "direct" || next.VPNServers[0].DefaultChannel == "" {
					t.Fatal("comparison mutated configuration")
				}
			})
		}
	}
}

func TestClientAccessConfirmationProtectsAdministrator(t *testing.T) {
	for _, mode := range []string{"other client", "filtered device", "unblock", "self", "self alternate MAC", "missing neighbour", "failed neighbour", "wrong interface", "wrong IP", "mixed filter"} {
		t.Run(mode, func(t *testing.T) {
			old, _ := configuredFirewall(t)
			old.Clients = []config.Client{{ID: "other", MAC: "02:00:00:00:00:03"}}
			if mode == "unblock" {
				old.Clients[0].Blocked = true
			}
			if mode == "self" {
				old.Clients[0].MAC = "02:00:00:00:00:02"
			}
			if mode == "self alternate MAC" {
				old.Clients[0].MAC = "02-00-00-00-00-02"
			}
			next := *old
			next.Clients = append([]config.Client(nil), old.Clients...)
			next.Clients[0].Blocked = !old.Clients[0].Blocked
			rs, err := Build(old)
			if err != nil {
				t.Fatal(err)
			}
			r := &confirmationRunner{firewallRunner: cleanFirewallRunner(rs), rules: "0: from all lookup local\n32766: from all lookup main", rpf: "2\n2", route: `[{"dev":"lan0"}]`, neighbours: `[{"dst":"192.0.2.2","dev":"lan0","lladdr":"02:00:00:00:00:02","state":["REACHABLE"]}]`}
			switch mode {
			case "filtered device":
				r.neighbours = strings.ReplaceAll(r.neighbours, `"dev":"lan0",`, "")
			case "missing neighbour":
				r.neighbours = "[]"
			case "failed neighbour":
				r.neighbours = strings.ReplaceAll(r.neighbours, "REACHABLE", "FAILED")
			case "wrong interface":
				r.neighbours = strings.ReplaceAll(r.neighbours, "lan0", "other0")
			case "wrong IP":
				r.neighbours = strings.ReplaceAll(r.neighbours, "192.0.2.2", "192.0.2.9")
			case "mixed filter":
				next.Firewall.OutputPolicy = "drop"
			}
			ctx := apply.WithManagementConnection(context.Background(), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
			actions, err := New(r, t.TempDir()).PlanContext(ctx, old, &next)
			if err != nil {
				t.Fatal(err)
			}
			for i := range actions {
				actions[i].Subsystem = "firewall"
			}
			want := mode == "other client" || mode == "filtered device" || mode == "unblock"
			if safe := !apply.NeedsConfirmation(actions); safe != want {
				t.Fatalf("safe=%v want=%v actions=%+v", safe, want, actions)
			}
		})
	}
}
