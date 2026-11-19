package config

import (
	"net/netip"
	"strings"
)

// Static configuration cannot prove reachability through DHCP or tunnels.
// This check supplies a warning, never rejects such routes as invalid.
func (c *Config) staticGatewayConnected(route StaticRoute, gateway netip.Addr, interfaceNames map[string]string) bool {
	contains := func(raw, iface string, allowHost bool) bool {
		if route.Interface != "" && route.Interface != iface {
			name, ok := interfaceNames[iface]
			if !ok {
				name = c.InterfaceName(iface)
				interfaceNames[iface] = name
			}
			if route.Interface != name {
				return false
			}
		}
		if allowHost && !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			return err == nil && addr == gateway
		}
		prefix, err := netip.ParsePrefix(raw)
		return err == nil && prefix.Contains(gateway)
	}
	for _, network := range c.Networks {
		if network.Enabled && contains(network.RouterAddress, network.Interface, false) {
			return true
		}
	}
	for _, wan := range c.WANs {
		if wan.Enabled && (wan.Proto == "static" || wan.Underlay == "static") && contains(wan.Address, wan.Interface, false) {
			return true
		}
	}
	for _, server := range c.VPNServers {
		if server.Enabled && route.Interface == "" && contains(server.Subnet, "", false) {
			return true
		}
	}
	table := staticTableKey(route.Table)
	for _, connected := range c.Routing.Static {
		if connected.Enabled && connected.Gateway == "" && connected.Interface != "" && (connected.Type == "" || connected.Type == "unicast") && staticTableKey(connected.Table) == table && contains(connected.Destination, connected.Interface, true) {
			return true
		}
	}
	return false
}
