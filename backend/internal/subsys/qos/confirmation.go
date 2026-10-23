package qos

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func (s *Subsystem) clientRatesSafe(ctx context.Context, old, next *config.Config) bool {
	if old == nil || !equalQoS(old.QoS, next.QoS) || !reflect.DeepEqual(old.Interfaces, next.Interfaces) || !reflect.DeepEqual(old.Networks, next.Networks) || !reflect.DeepEqual(old.WANs, next.WANs) {
		return false
	}
	before, err := desiredClientInterfaces(old)
	if err != nil {
		return false
	}
	after, err := desiredClientInterfaces(next)
	if err != nil || len(before) != len(after) {
		return false
	}
	changed := map[string]bool{}
	for i, item := range before {
		other := after[i]
		if item.Name != other.Name || len(item.Download) != len(other.Download) || len(item.Upload) != len(other.Upload) {
			return false
		}
		for _, pair := range [][2][]config.Client{{item.Download, other.Download}, {item.Upload, other.Upload}} {
			for j, client := range pair[0] {
				n := pair[1][j]
				if client.MAC != n.MAC || client.Network != n.Network {
					return false
				}
				if client.DownKbit != n.DownKbit || client.UpKbit != n.UpKbit {
					mac, err := net.ParseMAC(client.MAC)
					if err != nil || len(mac) != 6 {
						return false
					}
					changed[mac.String()] = true
				}
			}
		}
	}
	admin := s.managementMAC(ctx, next)
	if admin == "" || changed[admin] || s.Health(ctx, old) != nil {
		return false
	}
	for _, item := range after {
		if _, ok := s.clientRateUpdates(ctx, item); !ok {
			return false
		}
	}
	return true
}

func (s *Subsystem) managementMAC(ctx context.Context, cfg *config.Config) string {
	remote, local := apply.ManagementConnection(ctx)
	if !remote.Is4() || !local.Is4() || remote == local || remote.IsLoopback() || remote.IsUnspecified() || remote.IsMulticast() {
		return ""
	}
	iface := ""
	for _, network := range cfg.Networks {
		prefix, err := netip.ParsePrefix(network.RouterAddress)
		if err != nil || !network.Enabled || prefix.Addr() != local || !prefix.Contains(remote) {
			continue
		}
		for _, link := range cfg.Interfaces {
			if link.ID == network.Interface && link.Enabled {
				if iface != "" && iface != link.Name {
					return ""
				}
				iface = link.Name
			}
		}
	}
	if iface == "" || strings.ContainsAny(iface, "/\x00\r\n") {
		return ""
	}
	out, err := s.Runner.Run(ctx, "ip", "-4", "-j", "neigh", "show", "to", remote.String(), "dev", iface)
	if err != nil {
		return ""
	}
	var neighbours []struct {
		Dst, Dev, Lladdr string
		State            []string
	}
	if json.Unmarshal([]byte(out), &neighbours) != nil || len(neighbours) != 1 {
		return ""
	}
	n := neighbours[0]
	if n.Dst != remote.String() || (n.Dev != "" && n.Dev != iface) || len(n.State) == 0 {
		return ""
	}
	for _, state := range n.State {
		switch state {
		case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT":
		default:
			return ""
		}
	}
	mac, err := net.ParseMAC(n.Lladdr)
	if err != nil || len(mac) != 6 {
		return ""
	}
	return mac.String()
}
