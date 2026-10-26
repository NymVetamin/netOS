package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// WireGuardServerConfig contains server-only WireGuard settings. Peer keys are
// stored with the peer so every client can be enabled and routed independently.
type WireGuardServerConfig struct {
	PrivateKey       string   `json:"private_key" plan:"Закрытый ключ" sensitivity:"secret"`
	MTU              int      `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	PublicEndpoint   string   `json:"public_endpoint,omitempty" plan:"Публичный адрес подключения" sensitivity:"public"`
	ClientDNS        []string `json:"client_dns,omitempty" plan:"DNS для клиентов" sensitivity:"public"` // Legacy profile defaults, kept for existing clients.
	ClientAllowedIPs []string `json:"client_allowed_ips,omitempty" plan:"Маршруты клиентов" sensitivity:"public"`
}

// WireGuardClientProfile configures the exported client, not the server's peer
// AllowedIPs (which must continue to contain only that peer's tunnel address).
type WireGuardClientProfile struct {
	UseRouterDNS bool     `json:"use_router_dns" plan:"Использовать DNS роутера" sensitivity:"public"`
	DNS          []string `json:"dns" plan:"DNS" sensitivity:"public"`
	AllowedIPs   []string `json:"allowed_ips" plan:"Маршруты клиента" sensitivity:"public"`
}

func (s VPNServer) WireGuardProfileFor(peer VPNPeer) (WireGuardClientProfile, error) {
	var profile WireGuardClientProfile
	if peer.WireGuardProfile != nil {
		profile = *peer.WireGuardProfile
	} else {
		// Preserve already-issued profiles, including profiles with no DNS.
		wg, err := s.WireGuardConfig()
		if err != nil {
			return profile, err
		}
		profile.DNS, profile.AllowedIPs = wg.ClientDNS, wg.ClientAllowedIPs
		if len(profile.AllowedIPs) == 0 {
			profile.AllowedIPs = []string{"0.0.0.0/0"}
		}
	}
	if profile.UseRouterDNS {
		profile.DNS = []string{strings.SplitN(s.Subnet, "/", 2)[0]}
	}
	return profile, nil
}

// XrayServerConfig describes an authenticated Xray listener. An empty protocol
// keeps the original VLESS+Reality configuration used by existing installs.
type XrayServerConfig struct {
	Sniffing       bool     `json:"sniffing,omitempty" plan:"Определение протокола и назначения" sensitivity:"public"`
	Protocol       string   `json:"protocol,omitempty" plan:"Протокол" sensitivity:"public"`
	Listen         string   `json:"listen,omitempty" plan:"Адрес прослушивания" sensitivity:"public"`
	Method         string   `json:"method,omitempty" plan:"Метод шифрования" sensitivity:"public"`
	WGPrivateKey   string   `json:"wg_private_key,omitempty" plan:"Закрытый ключ WireGuard" sensitivity:"secret"`
	MTU            int      `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	PrivateKey     string   `json:"private_key" plan:"Закрытый ключ" sensitivity:"secret"`
	PublicEndpoint string   `json:"public_endpoint,omitempty" plan:"Публичный адрес подключения" sensitivity:"public"`
	Destination    string   `json:"destination" plan:"Назначение" sensitivity:"public"`
	ServerNames    []string `json:"server_names" plan:"Имена сервера TLS" sensitivity:"public"`
	ShortIDs       []string `json:"short_ids" plan:"Идентификаторы REALITY" sensitivity:"secret"`
	Flow           string   `json:"flow,omitempty" plan:"Режим flow" sensitivity:"public"`
	Show           bool     `json:"show,omitempty" plan:"Диагностика REALITY" sensitivity:"public"`
}

// OcservServerConfig contains user-visible OpenConnect server options. The
// certificate is generated and owned by netOS; per-user passwords live on
// VPNPeer credentials and are hashed before ocserv sees them.
type OcservServerConfig struct {
	AuthMode       string     `json:"auth_mode,omitempty" plan:"Режим авторизации" sensitivity:"public"` // password | certificate | certificate_password
	TLS            *OcservTLS `json:"tls,omitempty" plan:"TLS" sensitivity:"public"`
	UseRouterDNS   bool       `json:"use_router_dns,omitempty" plan:"Использовать DNS роутера" sensitivity:"public"`
	PublicEndpoint string     `json:"public_endpoint,omitempty" plan:"Публичный адрес подключения" sensitivity:"public"`
	DNS            []string   `json:"dns,omitempty" plan:"DNS" sensitivity:"public"`
	Routes         []string   `json:"routes,omitempty" plan:"Маршруты" sensitivity:"public"`
	MTU            int        `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	Banner         string     `json:"banner,omitempty" plan:"Приветствие" sensitivity:"public"`
}

func (s VPNServer) OcservAuthMode() string {
	oc, _ := s.OcservConfig()
	if oc.AuthMode == "" {
		return "password"
	}
	return oc.AuthMode
}

func (s VPNServer) OcservUsername(peer VPNPeer) string {
	if s.OcservAuthMode() != "password" {
		return "netos-" + peer.ID
	}
	return peer.Credentials["username"]
}

// OcservTLS is independent of client authentication. An absent value preserves
// the existing server certificate. "panel" reuses the panel's certificate only
// when it covers the VPN endpoint name.
type OcservTLS struct {
	Mode       string `json:"mode" plan:"Режим" sensitivity:"public"` // selfsigned | panel | acme | custom
	Domain     string `json:"domain,omitempty" plan:"Домен" sensitivity:"public"`
	Email      string `json:"email,omitempty" plan:"Электронная почта" sensitivity:"public"`
	AcceptTOS  bool   `json:"accept_tos,omitempty" plan:"Согласие с условиями ACME" sensitivity:"public"`
	CertPEM    string `json:"cert_pem,omitempty" plan:"Сертификат PEM" sensitivity:"public"`
	PrivateKey string `json:"private_key,omitempty" plan:"Закрытый ключ" sensitivity:"secret"`
}

func (c *Config) UsesACME() bool {
	if c.System.Panel.TLS.Mode == "acme" {
		return true
	}
	for _, server := range c.VPNServers {
		if server.Enabled && server.Type == "ocserv" {
			oc, err := server.OcservConfig()
			if err == nil && oc.TLS != nil && oc.TLS.Mode == "acme" {
				return true
			}
		}
	}
	return false
}

// IKEv2ServerConfig describes an IKEv2 road-warrior endpoint. Certificates
// are generated by netOS, while EAP-MSCHAPv2 credentials live on peers.
type IKEv2ServerConfig struct {
	PublicEndpoint string   `json:"public_endpoint,omitempty" plan:"Публичный адрес подключения" sensitivity:"public"`
	ServerIdentity string   `json:"server_identity,omitempty" plan:"Идентификатор сервера" sensitivity:"public"`
	DNS            []string `json:"dns,omitempty" plan:"DNS" sensitivity:"public"`
	SplitRoutes    []string `json:"split_routes,omitempty" plan:"Маршруты раздельного туннеля" sensitivity:"public"`
	MTU            int      `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
}

type L2TPServerConfig struct {
	Listen string `json:"listen" plan:"Адрес прослушивания" sensitivity:"public"`
	MTU    int    `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
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

func (s VPNServer) IKEv2Config() (IKEv2ServerConfig, error) {
	var out IKEv2ServerConfig
	data, err := json.Marshal(s.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров сервера IKEv2: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры сервера IKEv2: %w", err)
	}
	return out, nil
}

func (s VPNServer) L2TPConfig() (L2TPServerConfig, error) {
	var out L2TPServerConfig
	data, err := json.Marshal(s.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров сервера L2TP: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры сервера L2TP: %w", err)
	}
	return out, nil
}
