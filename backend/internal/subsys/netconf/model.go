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
	// Address — адрес роутера в сегменте, по имени интерфейса.
	Address map[string]string
	// Master — бридж или bond, которому подчинён интерфейс.
	Master map[string]config.Interface
	// VLANs — дочерние VLAN, по имени родительского интерфейса.
	VLANs map[string][]config.Interface
	// Uplink — интерфейсы аплинков: их поднимаем, но не настраиваем.
	Uplink map[string]bool
	// Names — имя интерфейса по идентификатору. Связи в конфигурации описаны
	// идентификаторами, а генераторы оперируют именами.
	Names map[string]string
	// SuppressIPv6 повторяет политику IPv6 из конфигурации.
	SuppressIPv6 bool
}

func buildPlan(cfg *config.Config) plan {
	p := plan{
		Address:      map[string]string{},
		Master:       map[string]config.Interface{},
		VLANs:        map[string][]config.Interface{},
		Uplink:       map[string]bool{},
		Names:        map[string]string{},
		SuppressIPv6: cfg.IPv6.Mode == "off",
	}

	byID := map[string]config.Interface{}
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface
		p.Names[iface.ID] = iface.Name
	}

	for _, n := range cfg.Networks {
		if !n.Enabled || n.RouterAddress == "" {
			continue
		}
		if iface, ok := byID[n.Interface]; ok {
			p.Address[iface.Name] = n.RouterAddress
		}
	}
	for _, w := range cfg.WANs {
		if !w.Enabled {
			continue
		}
		if iface, ok := byID[w.Interface]; ok {
			p.Uplink[iface.Name] = true
		}
	}

	// Members и Parent хранят идентификаторы: имя интерфейса администратор
	// меняет, а связь обязана это пережить. Здесь переводим их в имена — ими
	// оперируют и networkd, и ifupdown.
	for _, iface := range cfg.Interfaces {
		switch iface.Type {
		case "bridge", "bond":
			for _, member := range cfg.InterfaceNames(iface.Members) {
				p.Master[member] = iface
			}
		case "vlan":
			if parent := cfg.InterfaceName(iface.Parent); parent != "" {
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
