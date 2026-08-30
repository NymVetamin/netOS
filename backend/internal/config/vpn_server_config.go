package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// WireGuardServerConfig contains server-only WireGuard settings. Peer keys are
// stored with the peer so every client can be enabled and routed independently.
type WireGuardServerConfig struct {
	PrivateKey       string   `json:"private_key"`
	MTU              int      `json:"mtu,omitempty"`
	PublicEndpoint   string   `json:"public_endpoint,omitempty"`
	ClientDNS        []string `json:"client_dns,omitempty"`
	ClientAllowedIPs []string `json:"client_allowed_ips,omitempty"`
}

func (s VPNServer) WireGuardConfig() (WireGuardServerConfig, error) {
	var out WireGuardServerConfig
	data, err := json.Marshal(s.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров сервера WireGuard: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры сервера WireGuard: %w", err)
	}
	return out, nil
}
