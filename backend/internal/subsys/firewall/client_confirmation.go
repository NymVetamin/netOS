package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
)

func clientRoutingOnly(old, next *config.Config) bool {
	strip := func(c *config.Config) *config.Config {
		out := withoutRuleAnnotations(c)
		out.Clients = append([]config.Client(nil), c.Clients...)
		for i := range out.Clients {
			out.Clients[i].Channel = ""
		}
		out.Networks = append([]config.Network(nil), c.Networks...)
		for i := range out.Networks {
			out.Networks[i].DefaultChannel = ""
		}
		wireguard := map[string]bool{}
		out.VPNServers = append([]config.VPNServer(nil), c.VPNServers...)
		for i := range out.VPNServers {
			s := &out.VPNServers[i]
			if s.Type != "wireguard" {
				continue
			}
			wireguard[s.ID] = true
			s.DefaultChannel = ""
			s.Peers = append([]config.VPNPeer(nil), s.Peers...)
			for j := range s.Peers {
				s.Peers[j].Channel = ""
			}
		}
		out.Policies = nil
		for _, p := range c.Policies {
			if p.VPNServer != "" && !wireguard[p.VPNServer] {
				out.Policies = append(out.Policies, p)
			}
		}
		return out
	}
	a, err := Build(strip(old))
	if err != nil {
		return false
	}
	b, err := Build(strip(next))
	return err == nil && a.IPv4 == b.IPv4 && a.IPv6 == b.IPv6
}

// managementRoutingSafe verifies the reverse source lookup that Linux performs
// before accepting a new packet. Merely preserving INPUT rules is insufficient:
// src_valid_mark + rp_filter reject sources whose marked route is a blackhole.
// This is deliberately limited to a known direct IPv4 LAN management socket.
func (s *Subsystem) managementRoutingSafe(ctx context.Context, cfg *config.Config) bool {
	remote, local := apply.ManagementConnection(ctx)
	iface := managementLANInterface(ctx, cfg)
	if s.Runner == nil || iface == "" {
		return false
	}
	return s.managementReverseRoutesSafe(ctx, cfg, remote, local, iface)
}

func managementLANInterface(ctx context.Context, cfg *config.Config) string {
	remote, local := apply.ManagementConnection(ctx)
	if !remote.Is4() || !local.Is4() || remote.IsLoopback() || remote.IsUnspecified() || remote.IsMulticast() {
		return ""
	}
	iface := ""
	for _, n := range cfg.Networks {
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if err != nil || !n.Enabled || prefix.Addr() != local || !prefix.Contains(remote) || remote == local {
			continue
		}
		for _, link := range cfg.Interfaces {
			if link.ID == n.Interface && link.Enabled {
				if iface != "" && iface != link.Name {
					return ""
				}
				iface = link.Name
			}
		}
	}
	if iface == "" || strings.ContainsAny(iface, "/\x00\r\n") {
		return ""
	}
	return iface
}

func (s *Subsystem) managementReverseRoutesSafe(ctx context.Context, cfg *config.Config, remote, local netip.Addr, iface string) bool {
	rules, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(rules), "\n")
	if len(lines) == 0 || strings.Join(strings.Fields(lines[0]), " ") != "0: from all lookup local" {
		return false
	}
	// An iif/uid/port-dependent rule can make a userspace route query differ
	// from the kernel's source validation lookup. Do not infer safety for it.
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 5 || f[1] != "from" || f[2] != "all" {
			return false
		}
		if len(f) == 5 && f[3] == "lookup" {
			continue
		}
		if len(f) == 7 && f[3] == "fwmark" && f[5] == "lookup" {
			continue
		}
		if len(f) == 6 && f[3] == "fwmark" && f[5] == "blackhole" {
			continue
		}
		return false
	}
	rpf, err := s.Runner.Run(ctx, "sysctl", "-n", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf."+iface+".rp_filter")
	if err != nil {
		return false
	}
	values := strings.Fields(rpf)
	if len(values) != 2 {
		return false
	}
	for _, v := range values {
		if v != "0" && v != "2" {
			return false
		}
	}
	wanted := map[string]bool{}
	for _, c := range cfg.Clients {
		if !c.Blocked && c.Channel != "" {
			wanted[c.Channel] = true
		}
	}
	for _, n := range cfg.Networks {
		if n.Enabled && n.DefaultChannel != "" {
			wanted[n.DefaultChannel] = true
		}
	}
	wireguard := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "wireguard" {
			continue
		}
		wireguard[server.ID] = true
		if server.DefaultChannel != "" {
			wanted[server.DefaultChannel] = true
		}
		for _, peer := range server.Peers {
			if peer.Enabled && peer.Channel != "" {
				wanted[peer.Channel] = true
			}
		}
	}
	for _, p := range cfg.Policies {
		if p.Enabled && (p.VPNServer == "" || wireguard[p.VPNServer]) && p.Channel != "" {
			wanted[p.Channel] = true
		}
	}
	marks := []int{0}
	for id := range wanted {
		if id == "direct" {
			continue
		}
		found := false
		for _, ch := range cfg.Channels {
			if ch.ID == id && ch.Enabled {
				switch ch.Type {
				case "wireguard", "xray", "openconnect", "ikev2", "l2tp":
					marks = append(marks, channels.Mark(ch))
					found = true
				case "direct":
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	sort.Ints(marks)
	for _, mark := range marks {
		out, err := s.Runner.Run(ctx, "ip", "-4", "-j", "route", "get", remote.String(), "from", local.String(), "mark", fmt.Sprintf("0x%x", mark))
		if err != nil {
			return false
		}
		var routes []struct {
			Type string `json:"type"`
			Dev  string `json:"dev"`
		}
		if json.Unmarshal([]byte(out), &routes) != nil || len(routes) != 1 || routes[0].Dev == "" || (routes[0].Type != "" && routes[0].Type != "unicast") {
			return false
		}
	}
	return true
}

func clientAccessOnly(old, next *config.Config) bool {
	strip := func(c *config.Config) *config.Config {
		out := withoutRuleAnnotations(c)
		out.Clients = append([]config.Client(nil), c.Clients...)
		for i := range out.Clients {
			out.Clients[i].Blocked = false
		}
		return out
	}
	a, err := Build(strip(old))
	if err != nil {
		return false
	}
	b, err := Build(strip(next))
	return err == nil && a.IPv4 == b.IPv4 && a.IPv6 == b.IPv6
}

func (s *Subsystem) clientAccessSafe(ctx context.Context, old, next *config.Config) bool {
	if !s.managementRoutingSafe(ctx, next) {
		return false
	}
	previous := map[string]bool{}
	for _, c := range old.Clients {
		if c.Blocked {
			mac, err := net.ParseMAC(c.MAC)
			if err != nil || len(mac) != 6 {
				return false
			}
			previous[mac.String()] = true
		}
	}
	blocked := map[string]bool{}
	for _, c := range next.Clients {
		if c.Blocked {
			mac, err := net.ParseMAC(c.MAC)
			if err != nil || len(mac) != 6 {
				return false
			}
			if !previous[mac.String()] {
				blocked[mac.String()] = true
			}
		}
	}
	if len(blocked) == 0 {
		return true
	}
	remote, _ := apply.ManagementConnection(ctx)
	iface := managementLANInterface(ctx, next)
	out, err := s.Runner.Run(ctx, "ip", "-4", "-j", "neigh", "show", "to", remote.String(), "dev", iface)
	if err != nil {
		return false
	}
	var entries []struct {
		Dst   string   `json:"dst"`
		Dev   string   `json:"dev"`
		MAC   string   `json:"lladdr"`
		State []string `json:"state"`
	}
	if json.Unmarshal([]byte(out), &entries) != nil || len(entries) != 1 {
		return false
	}
	e := entries[0]
	// iproute2 omits dev when the command already filters by that interface.
	if e.Dst != remote.String() || (e.Dev != "" && e.Dev != iface) {
		return false
	}
	mac, err := net.ParseMAC(e.MAC)
	if err != nil || len(mac) != 6 {
		return false
	}
	valid := false
	for _, state := range e.State {
		switch state {
		case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT":
			valid = true
		default:
			return false
		}
	}
	return valid && !blocked[strings.ToLower(mac.String())]
}
