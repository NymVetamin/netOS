package config

import (
	"strings"
	"testing"
)

func TestXrayTCPRequiresResponseContract(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{ID: "xr-response", Index: 3, Name: "Xray", Enabled: true, Type: "xray", Mode: "tun", FailMode: "block", Config: map[string]any{"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}}}})
	for _, tc := range []struct {
		name, response string
		fail           bool
	}{{"missing", "", true}, {"prefix", "pong\n", false}, {"oversized", strings.Repeat("x", 4097), true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := validProbeOf("tcp", "192.0.2.1:8001")
			p.TCPRequest, p.TCPResponse = "ping\n", tc.response
			cfg.Channels[1].Probe = p
			found := false
			for _, problem := range cfg.Validate().Problems {
				if problem.Severity == "error" && problem.Path == "channels[1].probe.tcp_response" {
					found = true
				}
			}
			if found != tc.fail {
				t.Fatalf("response rejected=%v, want %v", found, tc.fail)
			}
		})
	}
}
