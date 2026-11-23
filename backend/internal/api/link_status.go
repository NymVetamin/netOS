package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/subsys/channels"
)

func (s *Server) liveLinks(ctx context.Context, cfg *config.Config, stats []runtime.InterfaceStat) (wans, tunnels []map[string]any) {
	if cfg == nil {
		return nil, nil
	}
	up := map[string]bool{}
	for _, stat := range stats {
		up[stat.Name] = stat.Up
	}
	var namesByID map[string]string
	for _, wan := range cfg.WANs {
		if !wan.Enabled {
			continue
		}
		name := ""
		if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
			name = "ppp-" + wan.ID
		} else if len(cfg.WANs) == 1 {
			name = cfg.InterfaceName(wan.Interface)
		} else {
			if namesByID == nil {
				namesByID = make(map[string]string, len(cfg.Interfaces))
				for i := range cfg.Interfaces {
					port := &cfg.Interfaces[i]
					if _, exists := namesByID[port.ID]; !exists {
						namesByID[port.ID] = port.Name
					}
				}
			}
			name = namesByID[wan.Interface]
		}
		probeDown := s.WANHealth != nil && s.WANHealth.ProbeDown(wan.ID)
		address := ""
		if name != "" && s.Collector != nil && s.Collector.Runner != nil {
			if out, err := s.Collector.Runner.Run(ctx, "ip", "-4", "-o", "addr", "show", "dev", name); err == nil {
				for _, line := range strings.Split(out, "\n") {
					fields := strings.Fields(line)
					for i, field := range fields {
						if field == "inet" && i+1 < len(fields) {
							address = fields[i+1]
							break
						}
					}
					if address != "" {
						break
					}
				}
			}
		}
		wans = append(wans, map[string]any{"id": wan.ID, "name": wan.Name, "interface": name, "address": address, "link_up": up[name], "probe_down": probeDown, "up": up[name] && !probeDown})
	}
	// Shared peer channels use their server's interface and have no independent
	// AWG parameters. Build this lookup once per snapshot, not per channel.
	awgServers := make(map[string]bool)
	peerKeys := make(map[[2]string]string)
	for _, ch := range cfg.Channels {
		if ch.Enabled && ch.Type == "wireguard" && ch.WireGuardPeer != nil {
			ref := ch.WireGuardPeer
			peerKeys[[2]string{ref.ServerID, ref.PeerID}] = ""
		}
	}
	for _, server := range cfg.VPNServers {
		if server.IsAmneziaWG() {
			awgServers[server.ID] = true
		}
		if len(peerKeys) == 0 || !server.Enabled || server.Type != "wireguard" {
			continue
		}
		for _, peer := range server.Peers {
			key := [2]string{server.ID, peer.ID}
			if _, wanted := peerKeys[key]; wanted && peer.Enabled {
				peerKeys[key] = peer.Credentials["public_key"]
			}
		}
	}
	for _, ch := range cfg.Channels {
		if !ch.Enabled || ch.Type == "direct" {
			continue
		}
		name := channels.InterfaceName(ch)
		active := up[name]
		if active && ch.Type == "wireguard" {
			tool := "wg"
			if ch.IsAmneziaWG() || (ch.WireGuardPeer != nil && awgServers[ch.WireGuardPeer.ServerID]) {
				tool = "awg"
			}
			peerKey := ""
			if ref := ch.WireGuardPeer; ref != nil {
				peerKey = peerKeys[[2]string{ref.ServerID, ref.PeerID}]
				active = peerKey != ""
			}
			active = active && s.recentWireGuardHandshake(ctx, tool, name, peerKey)
		}
		if active && ch.Type == "ikev2" {
			active = s.establishedIKEv2Channel(ctx, ch.Index)
		}
		probeDown := s.ChannelHealth != nil && s.ChannelHealth.ProbeDown(ch.ID)
		tunnels = append(tunnels, map[string]any{"id": ch.ID, "name": ch.Name, "interface": name, "probe_down": probeDown, "up": active && !probeDown})
	}
	return wans, tunnels
}

func (s *Server) establishedIKEv2Channel(ctx context.Context, index int) bool {
	if s.Collector == nil || s.Collector.Runner == nil {
		return false
	}
	uri := fmt.Sprintf("unix:///run/netos-ikev2-ch%d/charon.vici", index)
	out, err := s.Collector.Runner.Run(ctx, "/usr/sbin/swanctl", "--list-sas", "--uri", uri)
	return err == nil && strings.Contains(out, "ESTABLISHED") && strings.Contains(out, "INSTALLED")
}

func (s *Server) recentWireGuardHandshake(ctx context.Context, tool, name, peerKey string) bool {
	if s.Collector == nil || s.Collector.Runner == nil {
		return false
	}
	out, err := s.Collector.Runner.Run(ctx, tool, "show", name, "latest-handshakes")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || (peerKey != "" && fields[0] != peerKey) {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && seconds > 0 && time.Since(time.Unix(seconds, 0)) < 3*time.Minute {
			return true
		}
	}
	return false
}
