package multiwan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type failoverRoutingRunner struct{ *balanceStateRunner }

func (r failoverRoutingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	if name == "ip" && !strings.Contains(cmd, " table ") && (strings.HasPrefix(cmd, "-4 route del default") || strings.HasPrefix(cmd, "-4 route replace default")) {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "dev" {
				if args[2] == "del" {
					r.main[args[i+1]] = ""
				} else {
					r.main[args[i+1]] = strings.Join(args[3:], " ")
				}
				return "", nil
			}
		}
	}
	return r.balanceStateRunner.Run(ctx, name, args...)
}

func TestFailoverCanProbeRemoteTargetAfterDefaultWithdrawal(t *testing.T) {
	r := failoverRoutingRunner{&balanceStateRunner{
		main:   map[string]string{"wan0": "default via 192.0.2.1 dev wan0 metric 100", "wan1": "default via 198.51.100.1 dev wan1 metric 200"},
		routes: map[string]string{}, rules: map[string]string{},
	}}
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "failover"
	cfg.Interfaces = []config.Interface{{ID: "p", Name: "wan0"}, {ID: "b", Name: "wan1"}}
	cfg.WANs = []config.WAN{
		{ID: "primary", Interface: "p", Index: 2, Enabled: true, Probe: config.Probe{Enabled: true, FailThreshold: 1, RiseThreshold: 1, Interval: 1}},
		{ID: "backup", Interface: "b", Index: 3, Enabled: true},
	}
	c := New(r, t.TempDir(), testLogger{})
	ctx := context.Background()
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.rules["30002"], "oif wan0 lookup 3002") || !strings.Contains(r.routes["3002"], "via 192.0.2.1") {
		t.Fatalf("no independent route for interface-bound probes: rules=%v routes=%v", r.rules, r.routes)
	}
	state := &linkState{}
	c.states["primary"] = state
	c.record(ctx, cfg.WANs[0], "wan0", state, false, true)
	if r.main["wan0"] != "" || !state.Down {
		t.Fatal("primary default was not withdrawn")
	}
	c.Probe = func(_ context.Context, _ config.WAN, iface string) bool {
		return iface == "wan0" && strings.Contains(r.routes["3002"], "via 192.0.2.1 dev wan0")
	}
	c.pausedUntil = time.Time{}
	c.tick(ctx, cfg)
	if state.Down || r.main["wan0"] == "" {
		t.Fatal("healthy remote target could not restore the primary route")
	}
	r.main["wan0"] = "default via 192.0.2.254 dev wan0 metric 45000"
	state.Next = time.Time{}
	c.Probe = func(_ context.Context, _ config.WAN, iface string) bool {
		return iface == "wan0" && strings.Contains(r.routes["3002"], "via 192.0.2.254 dev wan0")
	}
	c.tick(ctx, cfg)
	if state.Down || strings.Contains(r.routes["3002"], "metric 45000") || strings.Contains(r.routes["3002"], "via 192.0.2.1 ") {
		t.Fatalf("DHCP gateway/metric change left a stale probe default: %s", r.routes["3002"])
	}
	if err := c.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MultiWAN.Mode = "balance"
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.rules["30002"], "oif") || !strings.Contains(r.rules["30002"], "fwmark 0x3002") {
		t.Fatalf("balance retained failover probe selector: %v", r.rules)
	}
	cfg.MultiWAN.Mode = "failover"
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.rules["30002"], "fwmark") || !strings.Contains(r.rules["30002"], "oif wan0") {
		t.Fatalf("failover retained balance mark selector: %v", r.rules)
	}
	cfg.MultiWAN.Enabled = false
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(r.rules) != 0 || r.routes["3002"] != "" || r.routes["3003"] != "" {
		t.Fatal("probe routes survived disable")
	}
}
