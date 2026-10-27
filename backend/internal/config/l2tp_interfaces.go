package config

import (
	"fmt"
	"net/netip"
)

// A stable name is assigned by pppd's synchronous pre-up hook after
// authentication. It fits IFNAMSIZ even for server index 9999.
func L2TPInterfacePrefix(index int) string { return fmt.Sprintf("pp%d-", index) }

func L2TPPeerInterface(index int, address string) string {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return ""
	}
	return fmt.Sprintf("%s%x", L2TPInterfacePrefix(index), ip.As4())
}

func (c *Config) normalizeL2TPInterfaceLinks() {
	aliases := map[string]string{}
	for _, server := range c.VPNServers {
		if server.Type == "l2tp" {
			aliases[fmt.Sprintf("ppp-srv%d", server.Index)] = L2TPInterfacePrefix(server.Index) + "+"
		}
	}
	translate := func(name *string) {
		if next, ok := aliases[*name]; ok {
			*name = next
		}
	}
	for i := range c.Firewall.Rules {
		translate(&c.Firewall.Rules[i].Interface)
		translate(&c.Firewall.Rules[i].OutInterface)
	}
	for i := range c.Firewall.NAT {
		translate(&c.Firewall.NAT[i].Interface)
	}
}
