package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"net"
)

func (b *builder) socksAccess(c *config.Config) {
	p := c.Socks
	if !p.Enabled {
		return
	}
	protos := []string{"tcp"}
	allow := func(match string) {
		for _, proto := range protos {
			b.line("-A INPUT %s -p %s --dport %d -m comment --comment %q -j ACCEPT", match, proto, p.Port, "SOCKS5: разрешённый доступ")
		}
	}
	allow("-i lo")
	selected := func(ids []string, id string) bool {
		for _, v := range ids {
			if v == id {
				return true
			}
		}
		return false
	}
	for _, n := range c.Networks {
		if !n.Enabled || !selected(p.Networks, n.ID) {
			continue
		}
		_, sub, e := net.ParseCIDR(n.RouterAddress)
		if e != nil {
			continue
		}
		allow("-i " + c.InterfaceName(n.Interface) + " -s " + sub.String())
	}
	for _, v := range c.VPNServers {
		if !v.Enabled || v.Type == "xray" || !selected(p.VPNs, v.ID) {
			continue
		}
		_, sub, e := net.ParseCIDR(v.Subnet)
		if e != nil {
			continue
		}
		match := "-i " + vpnservers.MatchInterfaceName(v)
		if v.Type == "ikev2" {
			match = "-m policy --dir in --pol ipsec"
		}
		allow(match + " -s " + sub.String())
	}
	if p.AllowWAN {
		for _, w := range c.WANs {
			if w.Enabled {
				allow("-i " + wanInterface(c, w))
			}
		}
	}
	for _, proto := range []string{"tcp"} {
		b.line("-A INPUT -p %s --dport %d -m comment --comment %q -j DROP", proto, p.Port, "SOCKS5: остальные сети запрещены")
		if needsServiceOutputAccept(c) {
			b.line("-A OUTPUT -p %s --sport %d -m conntrack --ctstate ESTABLISHED -j ACCEPT", proto, p.Port)
		}
	}
}
