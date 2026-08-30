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

// XrayServerConfig describes a VLESS+Reality listener. Client UUIDs live on
// peers, so they can be enabled and assigned to output channels separately.
type XrayServerConfig struct {
	PrivateKey     string   `json:"private_key"`
	PublicEndpoint string   `json:"public_endpoint,omitempty"`
	Destination    string   `json:"destination"`
	ServerNames    []string `json:"server_names"`
	ShortIDs       []string `json:"short_ids"`
	Flow           string   `json:"flow,omitempty"`
	Show           bool     `json:"show,omitempty"`
}

// OcservServerConfig contains user-visible OpenConnect server options. The
// certificate is generated and owned by netOS; per-user passwords live on
// VPNPeer credentials and are hashed before ocserv sees them.
type OcservServerConfig struct {
	PublicEndpoint string   `json:"public_endpoint,omitempty"`
	DNS            []string `json:"dns,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	Banner         string   `json:"banner,omitempty"`
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

func (s VPNServer) XrayConfig() (XrayServerConfig, error) {
	var out XrayServerConfig
	data, err := json.Marshal(s.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров сервера Xray: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры сервера Xray: %w", err)
	}
	return out, nil
}

func (s VPNServer) OcservConfig() (OcservServerConfig, error) {
	var out OcservServerConfig
	data, err := json.Marshal(s.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров сервера ocserv: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры сервера ocserv: %w", err)
	}
	return out, nil
}
