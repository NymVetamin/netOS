package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Samba publishes only explicitly selected volumes and LAN segments.
type Samba struct {
	Enabled   bool            `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Discovery bool            `json:"discovery" plan:"Обнаружение в сети" sensitivity:"public"`
	Workgroup string          `json:"workgroup" plan:"Рабочая группа" sensitivity:"public"`
	Networks  []string        `json:"networks" plan:"Локальные сети" sensitivity:"public"`
	VPNs      []string        `json:"vpns" plan:"VPN-сети" sensitivity:"public"`
	Volumes   []StorageVolume `json:"volumes" plan:"Тома" sensitivity:"public"`
	Users     []SambaUser     `json:"users" plan:"Пользователи" sensitivity:"public"`
	Shares    []SambaShare    `json:"shares" plan:"Общие папки" sensitivity:"public"`
}
type StorageVolume struct {
	ID         string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	UUID       string `json:"uuid" plan:"UUID" sensitivity:"secret"`
	Filesystem string `json:"filesystem" plan:"Файловая система" sensitivity:"public"`
	Enabled    bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
}
type SambaUser struct {
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	ID       string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name     string `json:"name" plan:"Название" sensitivity:"public"`
	Password string `json:"password,omitempty" plan:"Пароль" sensitivity:"secret"`
}
type SambaShare struct {
	ID       string   `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name     string   `json:"name" plan:"Название" sensitivity:"public"`
	Volume   string   `json:"volume" plan:"Том" sensitivity:"public"`
	Enabled  bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	ReadOnly bool     `json:"read_only" plan:"Только чтение" sensitivity:"public"`
	Users    []string `json:"users" plan:"Пользователи" sensitivity:"public"`
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
	type selection struct{ eligible, seen bool }
	vpns := map[string]selection{}
	for _, id := range s.VPNs {
		vpns[id] = selection{}
	}
	if len(vpns) > 0 {
		for _, v := range c.VPNServers {
			if entry, selected := vpns[v.ID]; selected && v.Enabled && v.Type != "xray" {
				entry.eligible = true
				vpns[v.ID] = entry
			}
		}
	}
	for _, id := range s.VPNs {
		entry := vpns[id]
		if !entry.eligible || entry.seen {
			r.errf("samba.vpns", "выберите включённый VPN-сервер с IP-туннелем, без повторов")
		}
		entry.seen = true
		vpns[id] = entry
	}
	networks := map[string]selection{}
	for _, id := range s.Networks {
		networks[id] = selection{}
	}
	if len(networks) > 0 {
		for _, n := range c.Networks {
			if entry, selected := networks[n.ID]; selected && n.Enabled && !n.Isolated && n.Zone != "wan" {
				entry.eligible = true
				networks[n.ID] = entry
			}
		}
	}
	for _, id := range s.Networks {
		entry := networks[id]
		if !entry.eligible || entry.seen {
			r.errf("samba.networks", "сеть %q должна быть включённой, неизолированной и локальной; повторы запрещены", id)
		}
		entry.seen = true
		networks[id] = entry
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
