package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// WireGuardChannelConfig — параметры одного исходящего WireGuard-туннеля.
// Config у Channel остаётся расширяемой JSON-картой для разных технологий,
// но каждая реализованная технология декодирует её в строгую структуру.
type WireGuardChannelConfig struct {
	Address             string   `json:"address"`
	PrivateKey          string   `json:"private_key"`
	PeerPublicKey       string   `json:"peer_public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
}

type OpenConnectChannelConfig struct {
	Server        string `json:"server"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Protocol      string `json:"protocol,omitempty"`
	AuthGroup     string `json:"authgroup,omitempty"`
	ServerCert    string `json:"servercert,omitempty"`
	MTU           int    `json:"mtu,omitempty"`
	NoDTLS        bool   `json:"no_dtls,omitempty"`
	NoSystemTrust bool   `json:"no_system_trust,omitempty"`
}

func (c Channel) WireGuardConfig() (WireGuardChannelConfig, error) {
	var out WireGuardChannelConfig
	data, err := json.Marshal(c.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров WireGuard: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры WireGuard: %w", err)
	}
	return out, nil
}

func (c Channel) OpenConnectConfig() (OpenConnectChannelConfig, error) {
	var out OpenConnectChannelConfig
	data, err := json.Marshal(c.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров OpenConnect: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры OpenConnect: %w", err)
	}
	return out, nil
}
