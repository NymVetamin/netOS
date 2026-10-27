package config

import (
	"net/netip"
	"sort"
)

// IPTV routes provider multicast through existing WAN and LAN objects.
// Empty Sources accepts any source on the selected upstream, never other links.
type IPTV struct {
	Enabled  bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Upstream string   `json:"upstream" plan:"Аплинк IPTV" sensitivity:"public" reference:"wan"`
	Networks []string `json:"networks" plan:"Локальные сети" sensitivity:"public"`
	Sources  []string `json:"sources" plan:"Сети источников провайдера" sensitivity:"public"`
}

func (c *Config) IPTVUpstream() string {
	for _, w := range c.WANs {
		if w.ID == c.IPTV.Upstream && w.Enabled && (w.Proto == "dhcp" || w.Proto == "static") {
			return c.InterfaceName(w.Interface)
		}
	}
	return ""
}

func (c *Config) IPTVNetworks() []Network {
	selected := map[string]bool{}
	for _, id := range c.IPTV.Networks {
		selected[id] = true
	}
	var out []Network
	for _, n := range c.Networks {
		if n.Enabled && selected[n.ID] {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (p IPTV) SourceNetworks() []string {
	if len(p.Sources) == 0 {
		return []string{"0.0.0.0/0"}
	}
	values := map[string]bool{}
	for _, value := range p.Sources {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
			values[prefix.Masked().String()] = true
		}
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (c *Config) validateIPTV(r *ValidationResult) {
	if !c.IPTV.Enabled {
		return
	}
	if !c.HasComponent("igmpproxy") {
		r.errf("iptv.enabled", "установите компонент IPTV")
	}
	up := c.IPTVUpstream()
	if up == "" {
		r.errf("iptv.upstream", "выберите включённый аплинк DHCP или статический IPv4; для отдельного VLAN создайте аплинк на нём")
	}
	if len(c.IPTV.Networks) == 0 {
		r.errf("iptv.networks", "выберите локальную сеть для IPTV")
	}
	type selection struct{ eligible, seen bool }
	selected := map[string]selection{}
	for _, id := range c.IPTV.Networks {
		selected[id] = selection{}
	}
	if len(selected) > 0 {
		for _, n := range c.Networks {
			entry, wanted := selected[n.ID]
			if !wanted || !n.Enabled {
				continue
			}
			iface, ok := c.InterfaceByID(n.Interface)
			prefix, err := netip.ParsePrefix(n.RouterAddress)
			entry.eligible = ok && iface.Enabled && iface.Name != up && err == nil && prefix.Addr().Is4()
			selected[n.ID] = entry
		}
	}
	for _, id := range c.IPTV.Networks {
		entry := selected[id]
		if !entry.eligible || entry.seen {
			r.errf("iptv.networks", "сеть %q выключена, повторяется или не подходит для IPTV", id)
		}
		entry.seen = true
		selected[id] = entry
	}
	for _, w := range c.WANs {
		if w.ID == c.IPTV.Upstream {
			if iface, ok := c.InterfaceByID(w.Interface); !ok || !iface.Enabled {
				r.errf("iptv.upstream", "интерфейс аплинка выключен или отсутствует")
			}
		}
	}
	for _, value := range c.IPTV.Sources {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() {
			r.errf("iptv.sources", "укажите IPv4-сеть источников, например 10.0.0.0/8: %q", value)
		}
	}
}
