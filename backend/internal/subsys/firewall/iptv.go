package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"net/netip"
)

func (b *builder) iptvAccess(c *config.Config) {
	if !c.IPTV.Enabled || c.IPTVUpstream() == "" {
		return
	}
	up := c.IPTVUpstream()
	sourceMatch := func(source string) string {
		if source == "0.0.0.0/0" {
			return ""
		}
		return " -s " + source
	}
	igmp := func(iface, source string) {
		b.line("-A INPUT -i %s%s -p igmp -d 224.0.0.0/4 -m comment --comment %q -j ACCEPT", iface, sourceMatch(source), "IPTV: подписки")
		if needsServiceOutputAccept(c) {
			b.line("-A OUTPUT -o %s -p igmp -d 224.0.0.0/4 -m comment --comment %q -j ACCEPT", iface, "IPTV: подписки")
		}
	}
	igmp(up, "0.0.0.0/0")
	for _, n := range c.IPTVNetworks() {
		iface := c.InterfaceName(n.Interface)
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if iface == "" || err != nil {
			continue
		}
		igmp(iface, prefix.Masked().String())
		for _, source := range c.IPTV.SourceNetworks() {
			b.line("-A FORWARD -i %s -o %s%s -p udp -m iprange --dst-range 224.0.1.0-239.255.255.255 -m comment --comment %q -j ACCEPT", up, iface, sourceMatch(source), "IPTV: поток провайдера")
		}
	}
}
