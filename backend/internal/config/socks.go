package config

import "strings"

type Socks struct {
	Enabled    bool            `json:"enabled"`
	Port       int             `json:"port"`
	Networks   []string        `json:"networks"`
	VPNs       []string        `json:"vpns"`
	AllowWAN   bool            `json:"allow_wan"`
	Auth       bool            `json:"auth"`
	Username   string          `json:"username"`
	Password   string          `json:"password,omitempty"`
	SecretsSet map[string]bool `json:"secrets_set,omitempty"`
	UDP        bool            `json:"udp"`
	Channel    string          `json:"channel"`
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
	for _, id := range s.Networks {
		found := false
		for _, n := range c.Networks {
			if n.ID == id && n.Enabled {
				found = true
			}
		}
		if !found {
			r.errf("socks.networks", "локальная сеть %q отсутствует или выключена", id)
		}
	}
	for _, id := range s.VPNs {
		found := false
		for _, v := range c.VPNServers {
			if v.ID == id && v.Enabled && v.Type != "xray" {
				found = true
			}
		}
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
