package config

import "net/netip"

// Static configuration cannot prove reachability through DHCP or tunnels.
// This check supplies a warning, never rejects such routes as invalid.
func (c *Config) staticGatewayConnected(route StaticRoute, gateway netip.Addr) bool {
	contains := func(raw, iface string) bool {
		if route.Interface != "" && route.Interface != iface && route.Interface != c.InterfaceName(iface) {
			return false
		}
		prefix, err := netip.ParsePrefix(raw)
		return err == nil && prefix.Contains(gateway)
	}
	for _, network := range c.Networks {
		if network.Enabled && contains(network.RouterAddress, network.Interface) {
			return true
		}
	}
	for _, wan := range c.WANs {
		if wan.Enabled && (wan.Proto == "static" || wan.Underlay == "static") && contains(wan.Address, wan.Interface) {
			return true
		}
	}
	for _, server := range c.VPNServers {
		if server.Enabled && route.Interface == "" && contains(server.Subnet, "") {
			return true
		}
	}
	for _, connected := range c.Routing.Static {
		if connected.Enabled && connected.Gateway == "" && connected.Interface != "" && (connected.Type == "" || connected.Type == "unicast") && connected.Table == route.Table && contains(connected.Destination, connected.Interface) {
			return true
		}
	}
	return false
}
