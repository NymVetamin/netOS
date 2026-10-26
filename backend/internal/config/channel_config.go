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
	Address             string   `json:"address" plan:"Адрес" sensitivity:"public"`
	PrivateKey          string   `json:"private_key" plan:"Закрытый ключ" sensitivity:"secret"`
	PeerPublicKey       string   `json:"peer_public_key" plan:"Открытый ключ сервера" sensitivity:"public"`
	PresharedKey        string   `json:"preshared_key,omitempty" plan:"Предварительно согласованный ключ" sensitivity:"secret"`
	Endpoint            string   `json:"endpoint" plan:"Адрес подключения" sensitivity:"public"`
	AllowedIPs          []string `json:"allowed_ips" plan:"Маршруты клиента" sensitivity:"public"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty" plan:"Интервал keepalive, с" sensitivity:"public"`
	MTU                 int      `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
}

type OpenConnectChannelConfig struct {
	Server        string `json:"server" plan:"Сервер" sensitivity:"public"`
	Username      string `json:"username" plan:"Логин" sensitivity:"public"`
	Password      string `json:"password" plan:"Пароль" sensitivity:"secret"`
	Protocol      string `json:"protocol,omitempty" plan:"Протокол" sensitivity:"public"`
	AuthGroup     string `json:"authgroup,omitempty" plan:"Группа авторизации" sensitivity:"public"`
	ServerCert    string `json:"servercert,omitempty" plan:"Отпечаток сертификата сервера" sensitivity:"public"`
	MTU           int    `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	NoDTLS        bool   `json:"no_dtls,omitempty" plan:"Отключить DTLS" sensitivity:"public"`
	NoSystemTrust bool   `json:"no_system_trust,omitempty" plan:"Не использовать системные сертификаты" sensitivity:"public"`
}

type L2TPChannelConfig struct {
	Server   string `json:"server" plan:"Сервер" sensitivity:"public"`
	Username string `json:"username" plan:"Логин" sensitivity:"public"`
	Password string `json:"password" plan:"Пароль" sensitivity:"secret"`
	MTU      int    `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
}

type IKEv2ChannelConfig struct {
	Server         string `json:"server" plan:"Сервер" sensitivity:"public"`
	ServerIdentity string `json:"server_identity" plan:"Идентификатор сервера" sensitivity:"public"`
	Username       string `json:"username" plan:"Логин" sensitivity:"public"`
	Password       string `json:"password" plan:"Пароль" sensitivity:"secret"`
	CACert         string `json:"ca_cert" plan:"Сертификат центра сертификации" sensitivity:"public"`
	MTU            int    `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
}

type XrayChannelConfig struct {
	MTU      int            `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	Outbound map[string]any `json:"outbound" plan:"Исходящее подключение Xray" sensitivity:"public"`
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

func (c Channel) L2TPConfig() (L2TPChannelConfig, error) {
	var out L2TPChannelConfig
	data, err := json.Marshal(c.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров L2TP: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры L2TP: %w", err)
	}
	return out, nil
}

func (c Channel) IKEv2Config() (IKEv2ChannelConfig, error) {
	var out IKEv2ChannelConfig
	data, err := json.Marshal(c.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров IKEv2: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры IKEv2: %w", err)
	}
	return out, nil
}

func (c Channel) XrayConfig() (XrayChannelConfig, error) {
	var out XrayChannelConfig
	data, err := json.Marshal(c.Config)
	if err != nil {
		return out, fmt.Errorf("кодирование параметров Xray: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("параметры Xray: %w", err)
	}
	return out, nil
}
