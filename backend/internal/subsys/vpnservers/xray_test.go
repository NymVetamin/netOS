package vpnservers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
)

func xrayServerConfig() (*config.Config, config.VPNServer) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "vpn", Index: 4, Name: "VPN", Enabled: true, Type: "wireguard"})
	server := config.VPNServer{
		ID: "reality", Index: 2, Name: "Reality", Enabled: true, Type: "xray", Port: 443,
		DefaultChannel: "direct", Subnet: "10.10.0.1/24",
		Config: map[string]any{
			"private_key": key, "destination": "www.example.com:443",
			"server_names": []string{"www.example.com"}, "short_ids": []string{"0123456789abcdef"},
		},
		Peers: []config.VPNPeer{
			{ID: "phone", Name: "Phone", Enabled: true, Address: "10.10.0.2", Channel: "vpn", Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}},
			{ID: "off", Name: "Off", Address: "10.10.0.3", Credentials: map[string]string{"uuid": "223e4567-e89b-12d3-a456-426614174000"}},
		},
	}
	return cfg, server
}

func TestRenderXrayRealityServerAndPeerChannel(t *testing.T) {
	cfg, server := xrayServerConfig()
	cfg.Policies = []config.Policy{{
		ID: "web", Name: "Web", Enabled: true, Priority: 10, Channel: "direct",
		VPNServer: server.ID, VPNPeer: "phone", Protocol: "tcp", DstPort: "443", DstIP: "1.1.1.0/24", Domains: []string{"Example.COM."},
	}}
	data, err := RenderXray(server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`"protocol": "vless"`, `"security": "reality"`, `"email": "reality/phone"`,
		`"outboundTag": "channel-vpn"`, `"mark": ` + fmt.Sprint(channels.Mark(cfg.Channels[1])),
		`"network": "tcp"`, `"port": "443"`, `"ip": [`, `"1.1.1.0/24"`, `"domain:example.com"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "223e4567") {
		t.Fatal("disabled peer rendered into Xray config")
	}
}
