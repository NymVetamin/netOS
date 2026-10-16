// Package monitor owns only accounting rules; it never accepts or drops traffic.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

const Table = "netos_traffic_monitor"
const Owner = "netOS traffic monitor v1"

type Subsystem struct{ Runner system.Runner }

// Clear removes only the table carrying our ownership marker.
func Clear(ctx context.Context, run func(context.Context, string, ...string) (string, error)) error {
	raw, err := run(ctx, "nft", "list", "table", "inet", Table)
	if err != nil {
		if missingTable(err) {
			return nil
		}
		return err
	}
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, Owner) {
		return fmt.Errorf("таблица %s не принадлежит netOS", Table)
	}
	_, err = run(ctx, "nft", "delete", "table", "inet", Table)
	return err
}

func (s *Subsystem) Name() string { return "traffic-monitor" }

func Interfaces(c *config.Config) []string {
	names := map[string]bool{}
	for _, n := range c.Networks {
		if n.Enabled {
			for _, i := range c.Interfaces {
				if i.ID == n.Interface && i.Enabled {
					names[i.Name] = true
				}
			}
		}
	}
	for _, v := range c.VPNServers {
		if v.Enabled && v.Type != "xray" {
			name := vpnservers.InterfaceName(v)
			if name != "" {
				if v.Type == "ocserv" {
					name += "*"
				}
				names[name] = true
			}
		}
	}
	out := []string{}
	for n := range names {
		if config.ValidInterfaceName(strings.TrimSuffix(n, "*")) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Keep counters when reapplying configuration. A separate late forward hook
// counts accepted IP traffic before SNAT, once per client side of a route.
func Render(c *config.Config, exists bool) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	if !c.TrafficMonitor.Enabled {
		if exists {
			w("delete table inet %s", Table)
		}
		return b.String()
	}
	if !exists {
		w("add table inet %s { comment %q; }", Table, Owner)
		for _, family := range []string{"4", "6"} {
			typ := "ipv4_addr"
			if family == "6" {
				typ = "ipv6_addr"
			}
			for _, dir := range []string{"up", "down"} {
				w("add set inet %s %s%s { type %s; flags dynamic,timeout; timeout 24h; size 4096; counter; }", Table, dir, family, typ)
			}
		}
		w("add chain inet %s clients { type filter hook forward priority 10; policy accept; }", Table)
	} else {
		w("flush chain inet %s clients", Table)
	}
	ifaces := Interfaces(c)
	if len(ifaces) > 0 {
		quoted := make([]string, len(ifaces))
		for i, iface := range ifaces {
			quoted[i] = fmt.Sprintf("%q", iface)
		}
		ifaceSet := "{ " + strings.Join(quoted, ", ") + " }"
		for _, family := range []string{"4", "6"} {
			proto, nf := "ip", "ipv4"
			if family == "6" {
				proto, nf = "ip6", "ipv6"
			}
			w("add rule inet %s clients iifname %s meta nfproto %s update @up%s { %s saddr timeout 24h counter }", Table, ifaceSet, nf, family, proto)
			w("add rule inet %s clients oifname %s meta nfproto %s update @down%s { %s daddr timeout 24h counter }", Table, ifaceSet, nf, family, proto)
		}
	}

	return b.String()
}
func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	if old != nil && Render(old, false) == Render(new, false) {
		return nil, nil
	}
	if old == nil && !new.TrafficMonitor.Enabled {
		return nil, nil
	}
	return []apply.Action{{Kind: "update", Target: "Монитор трафика", Detail: "счётчики клиентов и сбор истории"}}, nil
}
func (s *Subsystem) Apply(ctx context.Context, c *config.Config) error {
	if c.TrafficMonitor.Enabled {
		if _, err := system.NewPackages(s.Runner).Ensure(ctx, "nftables"); err != nil {
			return err
		}
	}
	raw, err := s.Runner.Run(ctx, "nft", "list", "table", "inet", Table)
	if err != nil && !missingTable(err) {
		return err
	}
	exists := err == nil
	if exists && !strings.Contains(raw, Owner) {
		return fmt.Errorf("таблица %s не принадлежит монитору netOS", Table)
	}
	if !exists && !c.TrafficMonitor.Enabled {
		return nil
	}
	script := Render(c, exists)
	_, err = s.Runner.RunInput(ctx, script, "nft", "-f", "-")
	return err
}
func (s *Subsystem) Health(ctx context.Context, c *config.Config) error {
	if !c.TrafficMonitor.Enabled {
		return nil
	}
	raw, err := s.Runner.Run(ctx, "nft", "list", "table", "inet", Table)
	if err != nil {
		return err
	}
	if !strings.Contains(raw, Owner) {
		return fmt.Errorf("счётчики монитора недоступны")
	}
	return nil
}

func missingTable(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "No such file or directory")
}
