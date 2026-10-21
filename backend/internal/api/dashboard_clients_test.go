package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestDashboardCountsLANAndVPNProfiles(t *testing.T) {
	s := &Server{vpnStatus: map[string]*vpnStatusCache{}}
	cfg := &config.Config{VPNServers: []config.VPNServer{
		{ID: "wg", Type: "wireguard", Enabled: true},
		{ID: "xr", Type: "xray", Enabled: true},
	}}
	for i, server := range cfg.VPNServers {
		data, _ := json.Marshal(server)
		rows := []vpnClientStatus{{ID: "phone", State: "recent"}, {ID: "off", State: "disabled"}}
		if i == 1 {
			rows = []vpnClientStatus{{ID: "phone", State: "online"}, {ID: "missing", State: "unknown"}, {ID: "old", State: "offline"}}
		}
		s.vpnStatus[server.ID] = &vpnStatusCache{fingerprint: sha256.Sum256(data), at: time.Now(), rows: rows}
	}
	got := s.dashboardClients(context.Background(), cfg, 3, 1)
	if got != (dashboardClients{LANTotal: 3, LANOnline: 1, VPNTotal: 5, VPNOnline: 2, VPNUnknown: 1}) {
		t.Fatalf("counts: %+v", got)
	}
	// Changing applied configuration invalidates the old online snapshot.
	cfg.VPNServers = []config.VPNServer{{ID: "xr", Type: "xray", Enabled: false, Peers: []config.VPNPeer{{ID: "phone", Enabled: true}}}}
	got = s.dashboardClients(context.Background(), cfg, 0, 0)
	if got.VPNTotal != 1 || got.VPNOnline != 0 || got.VPNUnknown != 0 {
		t.Fatalf("disabled: %+v", got)
	}
	got = s.dashboardClients(context.Background(), nil, 2, 1)
	if got.LANTotal != 2 || got.LANOnline != 1 || got.VPNTotal != 0 {
		t.Fatalf("no config: %+v", got)
	}
}
