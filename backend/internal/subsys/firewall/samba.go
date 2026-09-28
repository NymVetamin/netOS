package firewall

import (
	"net"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/samba"
)

func (b *builder) sambaAccess(c *config.Config) {
	if !c.Samba.Enabled {
		return
	}
	b.line("# --- Samba: selected LAN and authenticated VPN transports ---")
	b.line("-A INPUT -i lo -p tcp --dport 445 -j ACCEPT")
	for _, a := range samba.Accesses(c) {
		match := "-i " + a.Interface
		if a.IPsec {
			match = "-m policy --dir in --pol ipsec"
		}
		b.line("-A INPUT %s -s %s -p tcp --dport 445 -j ACCEPT", match, a.Subnet)
		b.line("-A OUTPUT -d %s -p tcp --sport 445 -m conntrack --ctstate ESTABLISHED -j ACCEPT", a.Subnet)
	}
	if c.Samba.Discovery {
		for _, n := range c.Networks {
			chosen := false
			for _, id := range c.Samba.Networks {
				if n.ID == id {
					chosen = true
				}
			}
			if !chosen || !n.Enabled {
				continue
			}
			iface := c.InterfaceName(n.Interface)
			_, subnet, err := net.ParseCIDR(n.RouterAddress)
			if err != nil {
				continue
			}
			b.line("-A INPUT -i %s -s %s -p udp --dport 3702 -j ACCEPT", iface, subnet.String())
			b.line("-A INPUT -i %s -s %s -p tcp --dport 3702 -j ACCEPT", iface, subnet.String())
			b.line("-A INPUT -i %s -p igmp -j ACCEPT", iface)
			b.line("-A OUTPUT -o %s -p igmp -j ACCEPT", iface)
			b.line("-A OUTPUT -o %s -d 239.255.255.250 -p udp --dport 3702 -j ACCEPT", iface)
			b.line("-A OUTPUT -o %s -p udp --sport 3702 -j ACCEPT", iface)
			b.line("-A OUTPUT -o %s -p tcp --sport 3702 -m conntrack --ctstate ESTABLISHED -j ACCEPT", iface)
		}
	}
	// These precede ordinary LAN accepts and ESTABLISHED so revoked access
	// cannot survive merely because its connection was already open.
	b.line("-A INPUT -p tcp -m multiport --dports 445,3702 -j DROP")
	b.line("-A INPUT -p udp --dport 3702 -j DROP")
}
