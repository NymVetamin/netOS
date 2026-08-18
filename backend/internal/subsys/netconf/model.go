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
	// SuppressIPv6 повторяет политику IPv6 из конфигурации.
	SuppressIPv6 bool
}

func buildPlan(cfg *config.Config) plan {
	p := plan{
		Address:      map[string]string{},
		Master:       map[string]config.Interface{},
		VLANs:        map[string][]config.Interface{},
		Uplink:       map[string]bool{},
		SuppressIPv6: cfg.IPv6.Mode == "off",
	}

	byID := map[string]config.Interface{}
	byName := map[string]config.Interface{}
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface
		byName[iface.Name] = iface
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

	for _, iface := range cfg.Interfaces {
		switch iface.Type {
		case "bridge", "bond":
			for _, member := range iface.Members {
				p.Master[member] = iface
			}
		case "vlan":
			if iface.Parent != "" {
				p.VLANs[iface.Parent] = append(p.VLANs[iface.Parent], iface)
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
