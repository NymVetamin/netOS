package config

import "testing"

func TestL2TPChannelCanBeUsedByPolicy(t *testing.T) {
	cfg := Default()
	cfg.Components = append(cfg.Components, Component{ID: "l2tp", Installed: true})
	cfg.Channels = append(cfg.Channels, Channel{ID: "l2tp", Index: 1, Name: "L2TP", Type: "l2tp", Enabled: true, Mode: "tun", FailMode: "block", Config: map[string]any{"server": "10.0.0.2", "username": "alice", "password": "secret"}})
	if !cfg.usableChannelIDs()["l2tp"] {
		t.Fatal("enabled L2TP channel is unavailable to policy routing")
	}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("valid L2TP channel rejected: %+v", result.Problems)
	}
}

func TestL2TPServerRejectsWANPortConflict(t *testing.T) {
	cfg := Default()
	cfg.Components = append(cfg.Components, Component{ID: "l2tp", Installed: true})
	cfg.VPNServers = []VPNServer{{ID: "l2tp", Index: 1, Name: "L2TP", Type: "l2tp", Enabled: true, Subnet: "10.99.0.1/24", Port: 1701, DefaultChannel: "direct", Config: map[string]any{"listen": "10.0.0.1"}, Peers: []VPNPeer{{ID: "alice", Name: "Alice", Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{"username": "alice", "password": "long-secret"}}}}}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("valid L2TP server rejected: %+v", result.Problems)
	}
	cfg.WANs = append(cfg.WANs, WAN{ID: "wan-l2tp", Name: "WAN L2TP", Proto: "l2tp", Enabled: true})
	if result := cfg.Validate(); !hasErrorAt(result, "vpn_servers[0].port") {
		t.Fatalf("L2TP WAN/server UDP 1701 conflict accepted: %+v", result.Problems)
	}
}
