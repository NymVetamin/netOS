package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Samba publishes only explicitly selected volumes and LAN segments.
type Samba struct {
	Enabled   bool            `json:"enabled"`
	Discovery bool            `json:"discovery"`
	Workgroup string          `json:"workgroup"`
	Networks  []string        `json:"networks"`
	VPNs      []string        `json:"vpns"`
	Volumes   []StorageVolume `json:"volumes"`
	Users     []SambaUser     `json:"users"`
	Shares    []SambaShare    `json:"shares"`
}
type StorageVolume struct {
	ID         string `json:"id"`
	UUID       string `json:"uuid"`
	Filesystem string `json:"filesystem"`
	Enabled    bool   `json:"enabled"`
}
type SambaUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
}
type SambaShare struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Volume   string   `json:"volume"`
	Enabled  bool     `json:"enabled"`
	ReadOnly bool     `json:"read_only"`
	Users    []string `json:"users"`
}

var sambaName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,19}$`)
var volumeUUID = regexp.MustCompile(`^[A-Fa-f0-9][A-Fa-f0-9-]{3,63}$`)

func (c *Config) validateSamba(r *ValidationResult) {
	s := c.Samba
	if s.Enabled && !c.HasComponent("samba") {
		r.errf("samba.enabled", "установите компонент Samba")
	}
	if s.Workgroup != "" && (!sambaName.MatchString(s.Workgroup) || len(s.Workgroup) > 15) {
		r.errf("samba.workgroup", "рабочая группа: до 15 латинских букв, цифр и подчёркиваний")
	}
	if s.Enabled && len(s.Networks) == 0 && len(s.VPNs) == 0 {
		r.errf("samba.networks", "выберите локальную сеть или VPN-сервер")
	}
	seenVPNs := map[string]bool{}
	for _, id := range s.VPNs {
		found := false
		for _, v := range c.VPNServers {
			if v.ID == id && v.Enabled && v.Type != "xray" {
				found = true
			}
		}
		if !found || seenVPNs[id] {
			r.errf("samba.vpns", "выберите включённый VPN-сервер с IP-туннелем, без повторов")
		}
		seenVPNs[id] = true
	}
	seenNetworks := map[string]bool{}
	for _, id := range s.Networks {
		found := false
		for _, n := range c.Networks {
			if n.ID == id && n.Enabled && !n.Isolated && n.Zone != "wan" {
				found = true
			}
		}
		if !found || seenNetworks[id] {
			r.errf("samba.networks", "сеть %q должна быть включённой, неизолированной и локальной; повторы запрещены", id)
		}
		seenNetworks[id] = true
	}
	volumes := map[string]StorageVolume{}
	uuids := map[string]bool{}
	for i, v := range s.Volumes {
		p := fmt.Sprintf("samba.volumes[%d]", i)
		if v.ID == "" || volumes[v.ID].ID != "" {
			r.errf(p+".id", "нужен уникальный ID")
		}
		if !volumeUUID.MatchString(v.UUID) || uuids[strings.ToLower(v.UUID)] {
			r.errf(p+".uuid", "нужен уникальный UUID файловой системы")
		}
		switch v.Filesystem {
		case "ext4", "ext3", "ext2", "vfat", "exfat", "ntfs":
		default:
			r.errf(p+".filesystem", "поддерживаются ext2/3/4, FAT, exFAT и NTFS")
		}
		volumes[v.ID] = v
		uuids[strings.ToLower(v.UUID)] = true
		if v.Enabled && !c.HasComponent("samba") {
			r.errf(p+".enabled", "установите компонент Samba")
		}
	}
	users := map[string]bool{}
	names := map[string]bool{}
	for i, u := range s.Users {
		p := fmt.Sprintf("samba.users[%d]", i)
		if u.ID == "" || users[u.ID] {
			r.errf(p+".id", "нужен уникальный ID")
		}
		if !sambaName.MatchString(u.Name) || names[strings.ToLower(u.Name)] {
			r.errf(p+".name", "уникальное имя: латинские буквы, цифры, подчёркивание, до 20 символов")
		}
		if len(u.Password) < 8 || len(u.Password) > 256 || strings.ContainsAny(u.Password, "\r\n\x00") {
			r.errf(p+".password", "пароль: от 8 до 256 байт, без переводов строк")
		}
		users[u.ID] = true
		names[strings.ToLower(u.Name)] = true
	}
	names = map[string]bool{}
	ids := map[string]bool{}
	for i, sh := range s.Shares {
		p := fmt.Sprintf("samba.shares[%d]", i)
		name := strings.ToLower(sh.Name)
		if sh.ID == "" || ids[sh.ID] {
			r.errf(p+".id", "нужен уникальный ID")
		}
		ids[sh.ID] = true
		if !sambaName.MatchString(sh.Name) || names[name] || name == "global" || name == "homes" || name == "printers" {
			r.errf(p+".name", "нужно уникальное имя папки: латинские буквы, цифры, подчёркивание")
		}
		names[name] = true
		v, ok := volumes[sh.Volume]
		if !ok || (sh.Enabled && !v.Enabled) {
			r.errf(p+".volume", "выберите существующий подключённый том")
		}
		if len(sh.Users) == 0 {
			r.errf(p+".users", "выберите пользователей с доступом")
		}
		seen := map[string]bool{}
		for _, id := range sh.Users {
			if !users[id] || seen[id] {
				r.errf(p+".users", "неизвестный или повторный пользователь")
			}
			seen[id] = true
		}
	}
}
