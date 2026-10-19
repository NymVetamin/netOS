package vpnservers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
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
	for _, raw := range document["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		settings := outbound["settings"].(map[string]any)
		finalRules := settings["finalRules"].([]any)
		if len(finalRules) != 1 || finalRules[0].(map[string]any)["action"] != "allow" {
			t.Fatalf("authenticated Reality outbound %q retains Xray's implicit private-address block: %#v", outbound["tag"], settings)
		}
	}
}

func TestRenderXrayAdditionalInboundProtocols(t *testing.T) {
	for _, tc := range []struct {
		protocol, want string
		credentials    map[string]string
	}{
		{"vless", `"security": "tls"`, map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}},
		{"vmess", `"protocol": "vmess"`, map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}},
		{"trojan", `"protocol": "trojan"`, map[string]string{"password": "long-password-123"}},
		{"shadowsocks", `"protocol": "shadowsocks"`, map[string]string{"password": "long-password-123"}},
		{"socks", `"protocol": "socks"`, map[string]string{"username": "alice", "password": "long-password"}},
		{"http", `"protocol": "http"`, map[string]string{"username": "alice", "password": "long-password"}},
		{"wireguard", `"protocol": "wireguard"`, map[string]string{"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		{"hysteria", `"protocol": "hysteria"`, map[string]string{"password": "long-password-123"}},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			cfg, server := xrayServerConfig()
			server.Config = map[string]any{"protocol": tc.protocol, "listen": "10.0.0.1", "method": "aes-256-gcm", "wg_private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			server.Peers = server.Peers[:1]
			server.Peers[0].Credentials = tc.credentials
			data, err := RenderXray(server, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.want) || strings.Contains(string(data), `"security": "reality"`) {
				t.Fatalf("wrong %s inbound: %s", tc.protocol, data)
			}
			if tc.protocol == "socks" || tc.protocol == "http" {
				if !strings.Contains(string(data), `"listen": "10.0.0.1"`) || !strings.Contains(string(data), `"inboundTag"`) {
					t.Fatalf("proxy bind or routing missing: %s", data)
				}
				cfg.Policies = []config.Policy{{ID: "proxy-policy", Name: "Proxy policy", Enabled: true, Priority: 10, Channel: "vpn", VPNServer: server.ID, VPNPeer: "phone"}}
				data, err = RenderXray(server, cfg)
				if err != nil || !strings.Contains(string(data), `"outboundTag": "channel-vpn"`) {
					t.Fatalf("proxy policy missing: %s %v", data, err)
				}
			}
			if tc.protocol == "vless" || tc.protocol == "trojan" || tc.protocol == "hysteria" {
				if !strings.Contains(string(data), `"certificateFile"`) || !strings.Contains(string(data), `"keyFile"`) {
					t.Fatalf("TLS certificate missing: %s", data)
				}
			}
		})
	}
}

func TestXrayIsolationOnEveryOutbound(t *testing.T) {
	cfg, server := xrayServerConfig()
	cfg.Networks = []config.Network{{ID: "lan", Enabled: true, Isolated: true, RouterAddress: "192.168.10.1/24"}, {ID: "other", Enabled: true, RouterAddress: "192.168.20.1/24"}}
	for _, isolated := range []bool{false, true} {
		server.Isolated = isolated
		data, err := RenderXray(server, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		json.Unmarshal(data, &doc)
		for _, raw := range doc["outbounds"].([]any) {
			rules := raw.(map[string]any)["settings"].(map[string]any)["finalRules"].([]any)
			if len(rules) != 2 || rules[0].(map[string]any)["action"] != "block" {
				t.Fatal("missing final deny")
			}
			ips := rules[0].(map[string]any)["ip"].([]any)
			expected := 1
			if isolated {
				expected = 2
			}
			if len(ips) != expected {
				t.Fatal(ips)
			}
		}
	}
	cfg.Firewall.Enabled = false
	data, _ := RenderXray(server, cfg)
	if strings.Contains(string(data), `"action": "block"`) {
		t.Fatal("disabled firewall still blocks")
	}
}

func TestXrayRouterDNS(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, port := range []int{53, 5353} {
			cfg, server := xrayServerConfig()
			cfg.DNS.Enabled, cfg.DNS.Port = enabled, port
			data, err := RenderXray(server, cfg)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			dns, exists := doc["dns"]
			if exists != enabled {
				t.Fatal("DNS enabled state ignored")
			}
			if enabled && dns.(map[string]any)["servers"].([]any)[0] != fmt.Sprintf("tcp+local://127.0.0.1:%d", port) {
				t.Fatal("wrong local DNS endpoint")
			}
			for _, raw := range doc["outbounds"].([]any) {
				outbound := raw.(map[string]any)
				stream, _ := outbound["streamSettings"].(map[string]any)
				sockopt, _ := stream["sockopt"].(map[string]any)
				if (sockopt["domainStrategy"] == "ForceIP") != enabled {
					t.Fatal("wrong resolution strategy")
				}
				if outbound["tag"] == "channel-vpn" && sockopt["mark"] != float64(channels.Mark(cfg.Channels[1])) {
					t.Fatal("channel mark lost")
				}
			}
		}
	}
}

func TestXrayResourceLoggingSwitch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg, server := xrayServerConfig()
		cfg.TrafficMonitor.Enabled = enabled
		data, err := RenderXray(server, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		json.Unmarshal(data, &doc)
		log := doc["log"].(map[string]any)
		if enabled {
			if log["dnsLog"] != true || log["access"] != "" {
				t.Fatal(log)
			}
		} else if log["access"] != "none" || log["dnsLog"] == true {
			t.Fatal(log)
		}
	}
}

func TestXrayMonitorTogglePlansRestart(t *testing.T) {
	old, server := xrayServerConfig()
	old.VPNServers = []config.VPNServer{server}
	next := *old
	next.TrafficMonitor.Enabled = !old.TrafficMonitor.Enabled
	actions, err := (&Subsystem{}).Plan(old, &next)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !actions[0].Disruptive || actions[0].Kind != "update" {
		t.Fatalf("missing logging restart: %+v", actions)
	}
}

func TestXraySniffingOption(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg, server := xrayServerConfig()
		server.Config["sniffing"] = enabled
		typed, err := server.XrayConfig()
		if err != nil || typed.Sniffing != enabled {
			t.Fatalf("sniffing config lost: %+v %v", typed, err)
		}
		data, err := RenderXray(server, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		in := doc["inbounds"].([]any)[0].(map[string]any)
		sn, exists := in["sniffing"]
		if exists != enabled {
			t.Fatalf("unexpected sniffing: %+v", in)
		}
		if enabled {
			value := sn.(map[string]any)
			if value["enabled"] != true || value["routeOnly"] != false || fmt.Sprint(value["destOverride"]) != "[http tls quic]" {
				t.Fatal(value)
			}
		}
		old, previous := xrayServerConfig()
		previous.Config["sniffing"] = !enabled
		old.VPNServers = []config.VPNServer{previous}
		cfg.VPNServers = []config.VPNServer{server}
		actions, err := (&Subsystem{}).Plan(old, cfg)
		if err != nil || len(actions) != 1 || actions[0].Kind != "update" || !actions[0].Disruptive {
			t.Fatalf("missing sniffing restart: %+v %v", actions, err)
		}
	}
}

func TestDNSQueryLogDoesNotChangeXray(t *testing.T) {
	for _, monitor := range []bool{false, true} {
		old, server := xrayServerConfig()
		old.TrafficMonitor.Enabled = monitor
		old.DNS.QueryLog = false
		server.Config["sniffing"] = true
		old.VPNServers = []config.VPNServer{server}
		next := *old
		next.DNS.QueryLog = true
		before, err := RenderXray(server, old)
		if err != nil {
			t.Fatal(err)
		}
		after, err := RenderXray(server, &next)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("DNS logging changed Xray config")
		}
		// No live services in this unit fixture: compare against the unchanged
		// plan, which may already contain a runtime-health repair action.
		baseline, err := (&Subsystem{}).Plan(old, old)
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]*config.Config{{old, &next}, {&next, old}} {
			actions, err := (&Subsystem{}).Plan(pair[0], pair[1])
			if err != nil || !reflect.DeepEqual(actions, baseline) {
				t.Fatalf("DNS logging restarted Xray: %+v %v", actions, err)
			}
		}
	}
}

func TestXrayClientFingerprintDoesNotChangeServer(t *testing.T) {
	cfg, server := xrayServerConfig()
	before, err := RenderXray(server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	changed := server
	changed.Peers = append([]config.VPNPeer(nil), server.Peers...)
	changed.Peers[0].TLSFingerprint = "firefox"
	after, err := RenderXray(changed, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || !sameServerRuntime(server, changed) {
		t.Fatal("client fingerprint changed server runtime")
	}
	if server.Peers[0].TLSFingerprint != "" || changed.Peers[0].TLSFingerprint != "firefox" {
		t.Fatal("comparison mutated configuration")
	}
	changed.Peers[0].Enabled = !changed.Peers[0].Enabled
	if sameServerRuntime(server, changed) {
		t.Fatal("real client change ignored")
	}
}
