package config

import "fmt"

// Membership includes disabled configuration objects: disabling a connection
// must not invalidate its saved firewall rules. Runtime expansion remains limited
// to active interfaces and fails closed when the selected exit is unavailable.
func (c *Config) FirewallInterfaceInZone(name, zone string) bool {
	return c.firewallInterfaceInZone(name, zone, c.InterfaceName)
}

func (c *Config) firewallInterfaceInZone(name, zone string, interfaceName func(string) string) bool {
	for _, n := range c.Networks {
		if n.Zone == zone && interfaceName(n.Interface) == name {
			return true
		}
	}
	if zone == "wan" {
		for _, w := range c.WANs {
			iface := interfaceName(w.Interface)
			if w.Proto == "pppoe" || w.Proto == "l2tp" {
				iface = "ppp-" + w.ID
			}
			if iface == name {
				return true
			}
		}
	}
	if zone == "vpn" {
		for _, ch := range c.Channels {
			prefix := map[string]string{"wireguard": "wg-ch", "l2tp": "ppp-ch", "ikev2": "xfrm-ch", "xray": "tun-ch", "openconnect": "tun-ch"}[ch.Type]
			if prefix != "" && name == fmt.Sprintf("%s%d", prefix, ch.Index) {
				return true
			}
		}
		for _, s := range c.VPNServers {
			if s.Type == "l2tp" && name == L2TPInterfacePrefix(s.Index)+"+" {
				return true
			}
			prefix := map[string]string{"wireguard": "wg-srv", "ikev2": "xfrm-srv", "ocserv": "vpns"}[s.Type]
			suffix := ""
			if s.Type == "ocserv" {
				suffix = "+"
			}
			if prefix != "" && name == fmt.Sprintf("%s%d%s", prefix, s.Index, suffix) {
				return true
			}
		}
	}
	return false
}
