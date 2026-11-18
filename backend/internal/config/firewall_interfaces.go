package config

import "fmt"

// ChannelInterface is the tunnel of an outgoing channel, or "" for a direct
// exit and an exit through a VPN-server client, whose interface is the
// server's own and stays in the VPN zone.
func ChannelInterface(ch Channel) string {
	if ch.WireGuardPeer != nil {
		return ""
	}
	prefix := map[string]string{"wireguard": "wg-ch", "l2tp": "ppp-ch", "ikev2": "xfrm-ch", "xray": "tun-ch", "openconnect": "tun-ch"}[ch.Type]
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s%d", prefix, ch.Index)
}

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
		// An outgoing channel is an Internet exit like an uplink.
		for _, ch := range c.Channels {
			if iface := ChannelInterface(ch); iface != "" && iface == name {
				return true
			}
		}
	}
	if zone == "vpn" {
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

// moveChannelRulesToWAN carries saved rules that name a channel tunnel from
// the VPN zone, where channels used to be, to the Internet zone. Left in place
// they would fail validation and block every later apply.
func (c *Config) moveChannelRulesToWAN() {
	channels := map[string]bool{}
	for _, ch := range c.Channels {
		if iface := ChannelInterface(ch); iface != "" {
			channels[iface] = true
		}
	}
	if len(channels) == 0 {
		return
	}
	for i := range c.Firewall.Rules {
		r := &c.Firewall.Rules[i]
		if r.Zone == "vpn" && channels[r.Interface] {
			r.Zone = "wan"
		}
		if r.DstZone == "vpn" && channels[r.OutInterface] {
			r.DstZone = "wan"
		}
	}
}
