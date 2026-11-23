package config

import (
	"net/netip"
	"strings"
)

// Static configuration cannot prove reachability through DHCP or tunnels.
// This check supplies a warning, never rejects such routes as invalid.
func (c *Config) staticGatewayConnected(route StaticRoute, gateway netip.Addr, interfaceNames map[string]string, prefixes map[string]netip.Prefix, direct *directRouteIndex) bool {
	contains := func(raw, iface string) bool {
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
		prefix, ok := prefixes[raw]
		if !ok {
			// An invalid prefix is the zero value and contains no address.
			prefix, _ = netip.ParsePrefix(raw)
			prefixes[raw] = prefix
		}
		return prefix.Contains(gateway)
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
	if direct.entries == nil {
		direct.build(c)
	}
	return direct.contains(staticTableKey(route.Table), route.Interface, gateway)
}

type directRouteKey struct {
	table, iface string
	address      netip.Addr
	bits         int // -1 for exact hosts, including their IPv6 zone
}

type directRouteIndex struct {
	entries map[directRouteKey]bool
	lengths map[int]bool
}

func (d *directRouteIndex) build(c *Config) {
	d.entries = make(map[directRouteKey]bool)
	d.lengths = make(map[int]bool)
	var names map[string]string
	for i := range c.Routing.Static {
		r := &c.Routing.Static[i]
		if !r.Enabled || r.Gateway != "" || r.Interface == "" || (r.Type != "" && r.Type != "unicast") {
			continue
		}
		key := directRouteKey{table: staticTableKey(r.Table), bits: -1}
		if strings.Contains(r.Destination, "/") {
			p, err := netip.ParsePrefix(r.Destination)
			if err != nil {
				continue
			}
			key.address, key.bits = p.Masked().Addr(), p.Bits()
			d.lengths[key.bits] = true
		} else {
			addr, err := netip.ParseAddr(r.Destination)
			if err != nil {
				continue
			}
			key.address = addr
		}
		if names == nil {
			names = make(map[string]string, len(c.Interfaces))
			for i := range c.Interfaces {
				port := &c.Interfaces[i]
				if _, exists := names[port.ID]; !exists {
					names[port.ID] = port.Name
				}
			}
		}
		d.entries[key] = true // query without an interface constraint
		key.iface = r.Interface
		d.entries[key] = true
		if alias := names[r.Interface]; alias != "" && alias != r.Interface {
			key.iface = alias
			d.entries[key] = true
		}
	}
}

func (d *directRouteIndex) contains(table, iface string, gateway netip.Addr) bool {
	key := directRouteKey{table: table, iface: iface, address: gateway, bits: -1}
	if d.entries[key] {
		return true
	}
	if gateway.Zone() != "" {
		return false // netip.Prefix.Contains excludes zoned addresses
	}
	for bits := range d.lengths {
		if bits <= gateway.BitLen() {
			key.bits = bits
			key.address = netip.PrefixFrom(gateway, bits).Masked().Addr()
			if d.entries[key] {
				return true
			}
		}
	}
	return false
}
