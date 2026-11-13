package monitor

import (
	"net/netip"
	"sort"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// ClientScope is a snapshot of configured client networks, never a cache of
// observed destinations. A VPN server interface may also carry exit traffic.
type ClientScope struct {
	links    map[string]map[netip.Prefix]struct{}
	prefixes map[netip.Prefix]struct{}
	bits     []int
}

func NewClientScope(c *config.Config) ClientScope {
	s := ClientScope{links: map[string]map[netip.Prefix]struct{}{}, prefixes: map[netip.Prefix]struct{}{}}
	lengths := map[int]bool{}
	add := func(name, raw string) {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !config.ValidInterfaceName(trimWildcard(name)) {
			return
		}
		p = p.Masked()
		if s.links[name] == nil {
			s.links[name] = map[netip.Prefix]struct{}{}
		}
		s.links[name][p] = struct{}{}
		s.prefixes[p] = struct{}{}
		lengths[p.Bits()] = true
	}
	interfaces := make(map[string]string, len(c.Interfaces))
	for _, i := range c.Interfaces {
		if i.Enabled {
			interfaces[i.ID] = i.Name
		}
	}
	for _, n := range c.Networks {
		if n.Enabled {
			if name := interfaces[n.Interface]; name != "" {
				add(name, n.RouterAddress)
			}
		}
	}
	for _, v := range c.VPNServers {
		if !v.Enabled || v.Type == "xray" {
			continue
		}
		name := vpnservers.InterfaceName(v)
		if v.Type == "ocserv" {
			name += "*"
		}
		add(name, v.Subnet)
	}
	for b := range lengths {
		s.bits = append(s.bits, b)
	}
	sort.Ints(s.bits)
	return s
}

func trimWildcard(name string) string {
	if len(name) > 0 && name[len(name)-1] == '*' {
		return name[:len(name)-1]
	}
	return name
}

// Contains has at most 129 hash lookups, independent of the number of clients
// or configured networks. Public client networks are valid too.
func (s ClientScope) Contains(raw string) bool {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	for _, bits := range s.bits {
		if bits > a.BitLen() {
			continue
		}
		if _, ok := s.prefixes[netip.PrefixFrom(a, bits).Masked()]; ok {
			return true
		}
	}
	return false
}
