package api

import (
	"context"

	"github.com/netos-router/netos/internal/config"
)

type dashboardClients struct {
	LANOnline  int `json:"lan_online"`
	LANTotal   int `json:"lan_total"`
	VPNOnline  int `json:"vpn_online"`
	VPNTotal   int `json:"vpn_total"`
	VPNUnknown int `json:"vpn_unknown"`
}

func (s *Server) dashboardClients(ctx context.Context, cfg *config.Config, total, online int) dashboardClients {
	counts := dashboardClients{LANTotal: total, LANOnline: online}
	if cfg == nil {
		return counts
	}
	for _, server := range cfg.VPNServers {
		// The same cached telemetry as Clients/Map; no second polling loop.
		for _, peer := range s.vpnClients(ctx, server) {
			counts.VPNTotal++
			switch peer.State {
			case "online", "recent":
				counts.VPNOnline++
			case "unknown":
				counts.VPNUnknown++
			}
		}
	}
	return counts
}
