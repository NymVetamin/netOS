package config

import "net/netip"

// InternalSegment is a routed client subnet, not an Internet exit channel.
type InternalSegment struct {
	ID, Name, Zone, Subnet string
	Isolated, VPN, Proxy   bool
}

func (c *Config) InternalSegments() []InternalSegment {
	var result []InternalSegment
	add := func(s InternalSegment, address string) {
		p, err := netip.ParsePrefix(address)
		if err != nil || !p.Addr().Is4() {
			return
		}
		s.Subnet = p.Masked().String()
		result = append(result, s)
	}
	for _, n := range c.Networks {
		if n.Enabled {
			add(InternalSegment{ID: "lan:" + n.ID, Name: n.Name, Zone: n.Zone, Isolated: n.Isolated}, n.RouterAddress)
		}
	}
	for _, s := range c.VPNServers {
		if s.Enabled {
			add(InternalSegment{ID: "vpn:" + s.ID, Name: s.Name, Zone: "vpn", Isolated: s.Isolated, VPN: true, Proxy: s.Type == "xray"}, s.Subnet)
		}
	}
	return result
}

// IsolationDestinations is also enforced on proxy outbounds, whose packets
// originate in OUTPUT and do not retain the VPN client's source address.
func (c *Config) IsolationDestinations(server VPNServer) []string {
	var result []string
	if !c.Firewall.Enabled {
		return result
	}
	add := func(address string) {
		p, err := netip.ParsePrefix(address)
		if err == nil && p.Addr().Is4() {
			result = append(result, p.Masked().String())
		}
	}
	for _, network := range c.Networks {
		if network.Enabled && (server.Isolated || network.Isolated) {
			add(network.RouterAddress)
		}
	}
	for _, destination := range c.VPNServers {
		if destination.Enabled && destination.ID != server.ID && (server.Isolated || destination.Isolated) {
			add(destination.Subnet)
		}
	}
	return result
}
