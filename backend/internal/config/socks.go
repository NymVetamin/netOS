package config

import "strings"

type Socks struct {
	Enabled    bool            `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Port       int             `json:"port" plan:"Порт" sensitivity:"public"`
	Networks   []string        `json:"networks" plan:"Локальные сети" sensitivity:"public"`
	VPNs       []string        `json:"vpns" plan:"VPN-сети" sensitivity:"public"`
	AllowWAN   bool            `json:"allow_wan" plan:"Доступ из интернета" sensitivity:"public"`
	Auth       bool            `json:"auth" plan:"Авторизация" sensitivity:"public"`
	Username   string          `json:"username" plan:"Логин" sensitivity:"public"`
	Password   string          `json:"password,omitempty" plan:"Пароль" sensitivity:"secret"`
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"`
	UDP        bool            `json:"udp" plan:"UDP" sensitivity:"public"`
	Channel    string          `json:"channel" plan:"Канал" sensitivity:"public" reference:"channel"`
}

func (c *Config) validateSocks(r *ValidationResult) {
	s := c.Socks
	if !s.Enabled {
		return
	}
	if s.UDP {
		r.errf("socks.udp", "SOCKS5 поддерживает только TCP; для передачи UDP используйте VPN")
	}
	if !c.HasComponent("xray") {
		r.errf("socks.enabled", "установите компонент Xray")
	}
	if !c.Firewall.Enabled {
		r.errf("socks.enabled", "для ограничения доступа к SOCKS5 включите защиту сети")
	}
	if s.Port < 1024 || s.Port > 65535 {
		r.errf("socks.port", "порт SOCKS5: от 1024 до 65535")
	}
	if s.Port == 5354 || s.Port == 5355 {
		r.errf("socks.port", "порт зарезервирован внутренними DNS-службами")
	}
	if s.AllowWAN && !s.Auth {
		r.errf("socks.allow_wan", "доступ с WAN требует логин и пароль")
	}
	if s.Auth && (len(s.Username) == 0 || len(s.Username) > 255 || len(s.Password) < 10 || len(s.Password) > 255 || strings.ContainsAny(s.Username+s.Password, "\r\n\x00")) {
		r.errf("socks.password", "задайте логин до 255 байт и пароль от 10 до 255 байт без управляющих символов")
	}
	if len(s.Networks) == 0 && len(s.VPNs) == 0 && !s.AllowWAN {
		r.errf("socks.networks", "выберите хотя бы одну сеть для доступа")
	}
	selectedNetworks := map[string]bool{}
	for _, id := range s.Networks {
		selectedNetworks[id] = false
	}
	if len(selectedNetworks) > 0 {
		for _, n := range c.Networks {
			if _, selected := selectedNetworks[n.ID]; selected && n.Enabled {
				selectedNetworks[n.ID] = true
			}
		}
	}
	for _, id := range s.Networks {
		found := selectedNetworks[id]
		if !found {
			r.errf("socks.networks", "локальная сеть %q отсутствует или выключена", id)
		}
	}
	selectedVPNs := map[string]bool{}
	for _, id := range s.VPNs {
		selectedVPNs[id] = false
	}
	if len(selectedVPNs) > 0 {
		for _, v := range c.VPNServers {
			if _, selected := selectedVPNs[v.ID]; selected && v.Enabled && v.Type != "xray" {
				selectedVPNs[v.ID] = true
			}
		}
	}
	for _, id := range s.VPNs {
		found := selectedVPNs[id]
		if !found {
			r.errf("socks.vpns", "выберите включённый VPN-сервер с IP-туннелем")
		}
	}
	found := false
	for _, ch := range c.Channels {
		if ch.ID == s.Channel && ch.Enabled {
			found = true
		}
	}
	if !found {
		r.errf("socks.channel", "выберите включённый канал выхода")
	}
}
