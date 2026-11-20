package netconf

import (
	"sort"

	"github.com/netos-router/netos/internal/config"
)

// plan — разобранная картина сети, одинаковая для обоих механизмов.
//
// Оба генератора отвечают на одни и те же вопросы: что это за интерфейс, есть
// ли у него адрес, кому он подчинён. Разбирать конфигурацию дважды значило бы
// однажды разойтись в ответах.
type plan struct {
	// Order — интерфейсы в порядке, в котором их безопасно поднимать:
	// подчинённые раньше агрегатов, родители VLAN раньше самих VLAN.
	Order []config.Interface
	// Addresses — адреса включённых сегментов по имени интерфейса.
	Addresses map[string][]string
	// Master — бридж или bond, которому подчинён интерфейс.
	Master map[string]config.Interface
	// VLANs — дочерние VLAN, по имени родительского интерфейса.
	VLANs map[string][]config.Interface
	// Uplink — интерфейсы аплинков: их поднимаем, но не настраиваем.
	Uplink map[string]bool
	// Names — имя интерфейса по идентификатору. Связи в конфигурации описаны
	// идентификаторами, а генераторы оперируют именами.
	Names   map[string]string
	Enabled map[string]bool
	// SuppressIPv6 повторяет политику IPv6 из конфигурации.
	SuppressIPv6 bool
}

func buildPlan(cfg *config.Config) plan {
	p := plan{
		Addresses:    map[string][]string{},
		Master:       map[string]config.Interface{},
		VLANs:        map[string][]config.Interface{},
		Uplink:       map[string]bool{},
		Names:        map[string]string{},
		Enabled:      cfg.InterfaceStates(),
		SuppressIPv6: cfg.IPv6.Mode == "off",
	}

	firstName := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		if _, seen := firstName[iface.ID]; !seen {
			firstName[iface.ID] = iface.Name
		}
		p.Names[iface.ID] = iface.Name
	}

	for _, n := range cfg.Networks {
		if !n.Enabled || n.RouterAddress == "" {
			continue
		}
		if name, ok := p.Names[n.Interface]; ok {
			p.Addresses[name] = append(p.Addresses[name], n.RouterAddress)
		}
	}
	for _, w := range cfg.WANs {
		if !w.Enabled {
			continue
		}
		if name, ok := p.Names[w.Interface]; ok {
			p.Uplink[name] = true
		}
	}

	// Members и Parent хранят идентификаторы: имя интерфейса администратор
	// меняет, а связь обязана это пережить. Здесь переводим их в имена — ими
	// оперируют и networkd, и ifupdown.
	for _, iface := range cfg.Interfaces {
		switch iface.Type {
		case "bridge", "bond":
			for _, id := range iface.Members {
				if member := firstName[id]; member != "" {
					p.Master[member] = iface
				}
			}
		case "vlan":
			if parent := firstName[iface.Parent]; parent != "" {
				p.VLANs[parent] = append(p.VLANs[parent], iface)
			}
		}
	}

	// Порядок поднятия: сначала физические порты, затем агрегаты, которым они
	// подчинены, затем VLAN поверх получившегося. Внутри группы — по имени,
	// чтобы файл не менялся от перестановки элементов в конфигурации и не
	// вызывал ложных перезаписей.
	for _, kind := range []string{"physical", "bond", "bridge", "vlan"} {
		var group []config.Interface
		for _, iface := range cfg.Interfaces {
			if iface.Type == kind {
				iface.Enabled = p.Enabled[iface.ID]
				group = append(group, iface)
			}
		}
		sort.Slice(group, func(i, j int) bool { return group[i].Name < group[j].Name })
		p.Order = append(p.Order, group...)
	}
	return p
}

// managedByNetOS сообщает, что адрес интерфейса назначает netOS, а не механизм
// системы: у аплинков это метрики, проверки живости и собственный клиент DHCP,
// вмешательство в которые сломало бы Multi-WAN.
func (p plan) managedByNetOS(iface config.Interface) bool {
	return p.Uplink[iface.Name]
}

// name переводит идентификатор интерфейса в имя.
func (p plan) name(id string) string { return p.Names[id] }

// names переводит список идентификаторов в имена, пропуская неизвестные.
func (p plan) namesOf(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := p.Names[id]; n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (p plan) enabledNamesOf(ids []string) []string {
	var out []string
	for _, id := range ids {
		if p.Enabled[id] && p.Names[id] != "" {
			out = append(out, p.Names[id])
		}
	}
	return out
}
