package render

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

func TestRemainingWireGuardServerArtifact(t *testing.T) {
	cfg := config.Default()
	server := config.VPNServer{ID: "srv", Index: 1, Name: "VPN", Enabled: true, Type: "wireguard", Port: 51820, Config: map[string]any{"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
	cfg.VPNServers = []config.VPNServer{server}
	for _, a := range Active(cfg) {
		if a.ID == "wireguard-servers" {
			got, err := a.Render(cfg)
			if err != nil {
				t.Fatal(err)
			}
			want, err := vpnservers.RenderWireGuard(server)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, want) {
				t.Fatal("artifact differs from runtime config")
			}
			return
		}
	}
	t.Fatal("WireGuard server absent from render catalog")
}
