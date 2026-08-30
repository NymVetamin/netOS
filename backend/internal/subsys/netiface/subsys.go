// Package netiface приводит канальный и сетевой уровень к описанному в
// конфигурации виду: создаёт бриджи, VLAN и bond, назначает адреса сегментам,
// поднимает аплинки.
//
// Работа идёт через команды ip из iproute2, а не через netlink напрямую.
// Причина практическая: каждое действие попадает в журнал ровно в том виде,
// в каком его можно повторить руками при разборе проблемы.
package netiface

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Interfaces управляет L2: бриджи, VLAN, bond, MTU, состояние up/down.
type Interfaces struct {
	Runner system.Runner
	// OwnedPath — файл со списком имён интерфейсов, которыми владеет netOS.
	//
	// Без него удаление моста и VLAN из панели не доходило до системы: понять,
	// что делать с интерфейсом, которого в конфигурации больше нет, можно
	// только помня, что он оттуда и взялся. Прежний код судил по префиксу
	// имени (br-, vl-), а имя задаёт администратор — мост «br1» под правило не
	// попадал и оставался в ip a навсегда.
	OwnedPath string

	// owned — список из OwnedPath, прочитанный в начале Apply.
	owned map[string]bool
}

// DefaultOwnedPath — где хранится список интерфейсов, созданных netOS.
const DefaultOwnedPath = "/var/lib/netos/owned-links"

func NewInterfaces(r system.Runner) *Interfaces {
	return &Interfaces{Runner: r, OwnedPath: DefaultOwnedPath}
}

func (s *Interfaces) Name() string { return "interfaces" }

func (s *Interfaces) Plan(old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action

	oldByID := map[string]config.Interface{}
	if old != nil {
		for _, i := range old.Interfaces {
			oldByID[i.ID] = i
		}
	}

	for _, iface := range new.Interfaces {
		prev, existed := oldByID[iface.ID]
		switch {
		case !existed && iface.Type != "physical":
			actions = append(actions, apply.Action{
				Kind: "create", Target: iface.Name,
				Detail: describeInterface(new, iface),
			})
		case existed && !reflect.DeepEqual(prev, iface):
			actions = append(actions, apply.Action{
				Kind: "update", Target: iface.Name,
				Detail: describeInterface(new, iface),
				// Переименование рвёт связность так же, как смена типа:
				// интерфейс со старым именем удаляется целиком.
				Disruptive: prev.Type != iface.Type || prev.VLANID != iface.VLANID ||
					prev.Name != iface.Name || prev.Parent != iface.Parent,
			})
		}
		delete(oldByID, iface.ID)
	}

	for _, gone := range oldByID {
		if gone.Type == "physical" {
			continue // физические порты не удаляем, только перестаём использовать
		}
		actions = append(actions, apply.Action{
			Kind: "delete", Target: gone.Name, Disruptive: true,
		})
	}
	return actions, nil
}

func (s *Interfaces) Apply(ctx context.Context, cfg *config.Config) error {
	// Лишнее убираем первым: переименованный мост занимает старое имя и держит
	// порты, а VLAN, у которого сменили номер или родителя, перевесить нельзя —
	// только пересоздать.
	if err := s.removeStale(ctx, cfg); err != nil {
		return err
	}

	// Дальше порядок важен: bond и bridge должны существовать до того, как в
	// них добавят порты, а родитель VLAN — до создания самого VLAN.
	for _, kind := range []string{"bond", "bridge", "vlan"} {
		for _, iface := range cfg.Interfaces {
			if iface.Type != kind {
				continue
			}
			if err := s.ensure(ctx, cfg, iface); err != nil {
				return err
			}
		}
	}

	for _, iface := range cfg.Interfaces {
		if err := s.configure(ctx, cfg, iface); err != nil {
			return err
		}
	}
	return s.rememberOwned(cfg)
}

// ensure создаёт виртуальный интерфейс, если его ещё нет.
func (s *Interfaces) ensure(ctx context.Context, cfg *config.Config, iface config.Interface) error {
	if linkExists(iface.Name) {
		mismatch := describeMismatch(cfg, iface)
		if mismatch == "" {
			return nil
		}
		// Имя занято интерфейсом, который не соответствует настройке. Свой —
		// пересоздаём: у VLAN нельзя на ходу сменить ни номер, ни родителя, и
		// без пересоздания панель показывала бы одно, а ip a другое.
		if !s.owned[iface.Name] {
			return fmt.Errorf("имя %s уже занято интерфейсом, который не создавал netOS (%s)",
				iface.Name, mismatch)
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "delete", iface.Name); err != nil {
			return fmt.Errorf("пересоздание %s (%s): %w", iface.Name, mismatch, err)
		}
	}
	switch iface.Type {
	case "bridge":
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", iface.Name, "type", "bridge"); err != nil {
			return fmt.Errorf("создание бриджа %s: %w", iface.Name, err)
		}
		// STP защищает от петли, если кто-то соединит два порта одного бриджа.
		_, _ = s.Runner.Run(ctx, "ip", "link", "set", iface.Name, "type", "bridge", "stp_state", "1")
	case "vlan":
		parent := cfg.InterfaceName(iface.Parent)
		if parent == "" {
			return fmt.Errorf("VLAN %s: родительский интерфейс не выбран", iface.Name)
		}
		if !linkExists(parent) {
			return fmt.Errorf("родительский интерфейс %s для VLAN %s не существует", parent, iface.Name)
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "link", parent,
			"name", iface.Name, "type", "vlan", "id", fmt.Sprint(iface.VLANID)); err != nil {
			return fmt.Errorf("создание VLAN %s: %w", iface.Name, err)
		}
	case "bond":
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", iface.Name, "type", "bond"); err != nil {
			return fmt.Errorf("создание bond %s: %w", iface.Name, err)
		}
	}
	return nil
}

// configure применяет параметры и членство в бридже/bond.
func (s *Interfaces) configure(ctx context.Context, cfg *config.Config, iface config.Interface) error {
	if !linkExists(iface.Name) {
		// Физический порт может отсутствовать: сетевую карту вынули или
		// переименовали. Это не повод валить всё применение.
		return nil
	}

	if iface.MTU > 0 {
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", iface.Name, "mtu", fmt.Sprint(iface.MTU)); err != nil {
			return fmt.Errorf("установка MTU для %s: %w", iface.Name, err)
		}
	}
	if iface.MAC != "" {
		_, _ = s.Runner.Run(ctx, "ip", "link", "set", iface.Name, "address", iface.MAC)
	}

	for _, member := range cfg.InterfaceNames(iface.Members) {
		if !linkExists(member) {
			continue
		}
		// Порт нельзя добавить в бридж, пока он состоит в другом; повторное
		// добавление в тот же безвредно.
		if current := masterOf(member); current == iface.Name {
			continue
		} else if current != "" {
			_, _ = s.Runner.Run(ctx, "ip", "link", "set", member, "nomaster")
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", member, "master", iface.Name); err != nil {
			return fmt.Errorf("добавление %s в %s: %w", member, iface.Name, err)
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", member, "up"); err != nil {
			return err
		}
	}

	// Бридж без единого порта не получает carrier и остаётся в состоянии
	// DOWN — значит, его адрес нерабочий, а DHCP на нём не поднимется. Так
	// бывает на машине с одной сетевой картой, где локальный сегмент нужен
	// для VPN-клиентов. Подставляем dummy-порт: он даёт бриджу carrier и
	// ничего больше не делает.
	if iface.Type == "bridge" && len(iface.Members) == 0 {
		if err := s.ensureBridgeCarrier(ctx, iface.Name); err != nil {
			return err
		}
	}

	// Порт, выведенный из моста в панели, обязан из него выйти и в системе:
	// иначе он остаётся подчинённым, его адрес не работает, а администратор
	// видит в панели свободный порт.
	if err := s.releaseFormerMembers(ctx, cfg, iface); err != nil {
		return err
	}

	state := "up"
	if !iface.Enabled {
		state = "down"
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", iface.Name, state); err != nil {
		return fmt.Errorf("перевод %s в состояние %s: %w", iface.Name, state, err)
	}
	return nil
}

// ensureBridgeCarrier создаёт dummy-порт для пустого бриджа.
func (s *Interfaces) ensureBridgeCarrier(ctx context.Context, bridge string) error {
	dummy := dummyNameFor(bridge)
	peer := carrierPeerNameFor(bridge)
	dummyExists, peerExists := linkExists(dummy), linkExists(peer)
	if dummyExists && !peerExists {
		if !s.owned[dummy] {
			return fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", dummy)
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "delete", dummy); err != nil {
			return fmt.Errorf("замена устаревшего carrier-порта %s: %w", dummy, err)
		}
		dummyExists = false
	}
	if peerExists && !dummyExists {
		return fmt.Errorf("интерфейс %s уже существует без парного %s", peer, dummy)
	}
	if dummyExists && (!s.owned[dummy] || !s.owned[peer]) {
		return fmt.Errorf("carrier-пара %s/%s не принадлежит netOS", dummy, peer)
	}
	if !dummyExists {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", dummy, "type", "veth", "peer", "name", peer); err != nil {
			return fmt.Errorf("создание carrier-пары для %s: %w", bridge, err)
		}
	}
	if masterOf(dummy) != bridge {
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", dummy, "master", bridge); err != nil {
			return fmt.Errorf("подключение dummy-порта к %s: %w", bridge, err)
		}
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", peer, "up"); err != nil {
		return err
	}
	_, err := s.Runner.Run(ctx, "ip", "link", "set", dummy, "up")
	return err
}

// dummyNameFor строит имя dummy-порта, укладываясь в лимит ядра в 15 символов.
func dummyNameFor(bridge string) string {
	name := "d-" + strings.TrimPrefix(bridge, "br-")
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func carrierPeerNameFor(bridge string) string {
	name := "p-" + strings.TrimPrefix(bridge, "br-")
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

// removeStale удаляет интерфейсы, которыми netOS владеет, но которых больше
// нет в конфигурации. Чужие интерфейсы не трогаем.
//
// Владение определяется не по имени, а по списку в OwnedPath: имя задаёт
// администратор, и мост «br1» под шаблон «br-*» не попадал — удаление из
// панели до системы не доходило вовсе.
func (s *Interfaces) removeStale(ctx context.Context, cfg *config.Config) error {
	_, ownedStatErr := os.Stat(s.OwnedPath)
	migrateLegacy := s.OwnedPath != "" && os.IsNotExist(ownedStatErr)
	s.owned = s.loadOwned()
	wanted := wantedLinks(cfg)

	stale := map[string]bool{}
	for name := range s.owned {
		if !wanted[name] {
			stale[name] = true
		}
	}
	// Установки прежних версий списка не имеют: там владение определялось
	// префиксом имени. Эту миграцию выполняем ровно один раз, пока файла ещё
	// нет. Пустой существующий файл — полноценный маркер завершённой миграции.
	// Иначе Interfaces при каждом Apply удаляла живые TUN других подсистем,
	// после чего неизменённый Xray/OpenConnect не перезапускался.
	if migrateLegacy {
		names, err := listLinks()
		if err != nil {
			return err
		}
		for _, name := range names {
			if !wanted[name] && isLegacyManagedName(name) {
				stale[name] = true
			}
		}
	}

	for name := range stale {
		if !linkExists(name) {
			continue
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "delete", name); err != nil {
			// Интерфейс мог исчезнуть сам: вынули карту, ушёл модуль. Валить
			// из-за этого всё применение незачем.
			continue
		}
	}
	return nil
}

// releaseFormerMembers выводит из моста или агрегации порты, которых больше нет
// в её составе. Без этого снятая в панели галочка не доходила до системы:
// порт оставался подчинённым, а его собственный адрес не работал.
func (s *Interfaces) releaseFormerMembers(ctx context.Context, cfg *config.Config, iface config.Interface) error {
	if iface.Type != "bridge" && iface.Type != "bond" {
		return nil
	}
	keep := map[string]bool{}
	for _, name := range cfg.InterfaceNames(iface.Members) {
		keep[name] = true
	}
	if len(iface.Members) == 0 {
		keep[dummyNameFor(iface.Name)] = true
	}
	for _, port := range slavesOf(iface.Name) {
		if keep[port] {
			continue
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", port, "nomaster"); err != nil {
			return fmt.Errorf("вывод %s из %s: %w", port, iface.Name, err)
		}
	}
	return nil
}

// wantedLinks — имена, которые обязаны существовать после применения.
func wantedLinks(cfg *config.Config) map[string]bool {
	wanted := map[string]bool{}
	for _, i := range cfg.Interfaces {
		wanted[i.Name] = true
		// Dummy-порт живёт ровно столько, сколько бридж остаётся пустым: как
		// только в него добавят настоящий порт, dummy будет удалён.
		if i.Type == "bridge" && len(i.Members) == 0 {
			wanted[dummyNameFor(i.Name)] = true
			wanted[carrierPeerNameFor(i.Name)] = true
		}
	}
	return wanted
}

// rememberOwned записывает, какими интерфейсами netOS владеет сейчас. Список
// переживает перезагрузку и обновление: без него удаление из панели опять
// перестало бы доходить до системы.
func (s *Interfaces) rememberOwned(cfg *config.Config) error {
	if s.OwnedPath == "" {
		return nil
	}
	var names []string
	for _, i := range cfg.Interfaces {
		if i.Type == "physical" {
			continue // порт существует и без нас
		}
		names = append(names, i.Name)
		if i.Type == "bridge" && len(i.Members) == 0 {
			names = append(names, dummyNameFor(i.Name))
			names = append(names, carrierPeerNameFor(i.Name))
		}
	}
	sort.Strings(names)
	s.owned = map[string]bool{}
	for _, n := range names {
		s.owned[n] = true
	}
	data := []byte(strings.Join(names, "\n"))
	if len(names) > 0 {
		data = append(data, '\n')
	}
	if err := system.WriteFileAtomic(s.OwnedPath, data, 0o644); err != nil {
		return fmt.Errorf("запись списка интерфейсов netOS: %w", err)
	}
	return nil
}

func (s *Interfaces) loadOwned() map[string]bool {
	owned := map[string]bool{}
	if s.OwnedPath == "" {
		return owned
	}
	data, err := os.ReadFile(s.OwnedPath)
	if err != nil {
		// Файла нет при первом применении и на установке прежней версии.
		return owned
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			owned[line] = true
		}
	}
	return owned
}

func (s *Interfaces) Health(ctx context.Context, cfg *config.Config) error {
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Type == "physical" {
			continue
		}
		if !linkExists(iface.Name) {
			return fmt.Errorf("интерфейс %s не создан", iface.Name)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Networks — адреса L3-сегментов
// ---------------------------------------------------------------------------

type Networks struct {
	Runner system.Runner
}

func NewNetworks(r system.Runner) *Networks { return &Networks{Runner: r} }

func (s *Networks) Name() string { return "networks" }

func (s *Networks) Plan(old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action
	oldByID := map[string]config.Network{}
	if old != nil {
		for _, n := range old.Networks {
			oldByID[n.ID] = n
		}
	}
	for _, n := range new.Networks {
		prev, existed := oldByID[n.ID]
		if !existed {
			actions = append(actions, apply.Action{
				Kind: "create", Target: n.Name, Detail: n.RouterAddress,
			})
		} else if prev.RouterAddress != n.RouterAddress || prev.Interface != n.Interface || prev.Enabled != n.Enabled {
			actions = append(actions, apply.Action{
				Kind: "update", Target: n.Name,
				Detail:     fmt.Sprintf("%s → %s", prev.RouterAddress, n.RouterAddress),
				Disruptive: true,
			})
		}
		delete(oldByID, n.ID)
	}
	for _, gone := range oldByID {
		actions = append(actions, apply.Action{
			Kind: "delete", Target: gone.Name, Detail: gone.RouterAddress, Disruptive: true,
		})
	}
	return actions, nil
}

func (s *Networks) Apply(ctx context.Context, cfg *config.Config) error {
	ifaceName := map[string]string{}
	for _, i := range cfg.Interfaces {
		ifaceName[i.ID] = i.Name
	}

	// Собираем желаемые адреса по интерфейсам, чтобы за один проход снять
	// лишние и добавить недостающие.
	wanted := map[string]map[string]bool{}
	wanIfaces := map[string]bool{}
	for _, w := range cfg.WANs {
		if w.Enabled {
			wanIfaces[w.Interface] = true
		}
	}
	// Пустой желаемый набор тоже значим: если с интерфейса удалили последний
	// LAN-сегмент, старый адрес должен быть снят. Аплинки обработает WAN ниже.
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || wanIfaces[iface.ID] || !linkExists(iface.Name) {
			continue
		}
		wanted[iface.Name] = map[string]bool{}
	}
	for _, n := range cfg.Networks {
		if !n.Enabled {
			continue
		}
		name := ifaceName[n.Interface]
		if name == "" || !linkExists(name) {
			continue
		}
		if wanted[name] == nil {
			wanted[name] = map[string]bool{}
		}
		wanted[name][n.RouterAddress] = true
	}

	for iface, addrs := range wanted {
		current, err := addressesOf(ctx, s.Runner, iface)
		if err != nil {
			return err
		}
		for addr := range addrs {
			if current[addr] {
				continue
			}
			if _, err := s.Runner.Run(ctx, "ip", "addr", "add", addr, "dev", iface); err != nil {
				return fmt.Errorf("назначение адреса %s на %s: %w", addr, iface, err)
			}
		}
		// Адреса, которых больше нет в конфигурации, снимаем — иначе после
		// смены подсети роутер останется доступен и по старому адресу.
		for addr := range current {
			if !addrs[addr] {
				_, _ = s.Runner.Run(ctx, "ip", "addr", "del", addr, "dev", iface)
			}
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", iface, "up"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Networks) Health(ctx context.Context, cfg *config.Config) error {
	ifaceName := map[string]string{}
	for _, i := range cfg.Interfaces {
		ifaceName[i.ID] = i.Name
	}
	for _, n := range cfg.Networks {
		if !n.Enabled {
			continue
		}
		name := ifaceName[n.Interface]
		if name == "" || !linkExists(name) {
			continue
		}
		current, err := addressesOf(ctx, s.Runner, name)
		if err != nil {
			return err
		}
		if !current[n.RouterAddress] {
			return fmt.Errorf("адрес %s не назначен на %s", n.RouterAddress, name)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// WAN — аплинки
// ---------------------------------------------------------------------------

type WAN struct {
	Runner system.Runner
	// pppoePrevious хранит конфигурации PPPoE, какими они были до применения:
	// по ним видно, менялись ли параметры, и живую сессию не приходится рвать
	// на каждом применении.
	pppoePrevious map[string]string
	// PPPoETimeout ограничивает ожидание сессии после применения, PPPoePoll —
	// как часто проверять. Значения по умолчанию подставляются на месте;
	// поля существуют, чтобы тесты не ждали десятки секунд.
	PPPoETimeout time.Duration
	PPPoePoll    time.Duration
}

func NewWAN(r system.Runner) *WAN { return &WAN{Runner: r} }

func (s *WAN) Name() string { return "wan" }

func (s *WAN) Plan(old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action
	oldByID := map[string]config.WAN{}
	if old != nil {
		for _, w := range old.WANs {
			oldByID[w.ID] = w
		}
	}
	for _, w := range new.WANs {
		prev, existed := oldByID[w.ID]
		if !existed {
			actions = append(actions, apply.Action{
				Kind: "create", Target: w.Name, Detail: w.Proto, Disruptive: true,
			})
		} else if !reflect.DeepEqual(prev, w) {
			actions = append(actions, apply.Action{
				Kind: "update", Target: w.Name, Detail: w.Proto, Disruptive: true,
			})
		}
		delete(oldByID, w.ID)
	}
	for _, gone := range oldByID {
		actions = append(actions, apply.Action{Kind: "delete", Target: gone.Name, Disruptive: true})
	}
	return actions, nil
}

func (s *WAN) Apply(ctx context.Context, cfg *config.Config) error {
	// Fail before looking at host interfaces. Besides producing a useful error
	// on incomplete/test systems, this prevents an unsupported enabled uplink
	// from being silently skipped merely because its link is currently absent.
	for _, w := range cfg.WANs {
		if !w.Enabled {
			continue
		}
		switch w.Proto {
		case "static", "dhcp", "pppoe", "l2tp":
		default:
			return fmt.Errorf("аплинк %s: неизвестный тип подключения %q", w.Name, w.Proto)
		}
	}
	ifaceName := map[string]string{}
	for _, i := range cfg.Interfaces {
		ifaceName[i.ID] = i.Name
	}
	dhcpWanted := map[string]bool{}
	pppoeWanted := map[string]bool{}
	l2tpWanted := map[string]bool{}
	for _, w := range cfg.WANs {
		if !w.Enabled || ifaceName[w.Interface] == "" {
			continue
		}
		switch w.Proto {
		case "dhcp":
			dhcpWanted[ifaceName[w.Interface]] = true
		case "pppoe":
			pppoeWanted[w.ID] = true
		case "l2tp":
			l2tpWanted[w.ID] = true
			// Туннель идёт поверх адреса в сети провайдера. Если тот приходит
			// по DHCP, клиент на этом интерфейсе нужен так же, как и обычному
			// аплинку.
			if w.Underlay != "static" {
				dhcpWanted[ifaceName[w.Interface]] = true
			}
		}
	}
	if err := s.cleanupDHCPClients(ctx, dhcpWanted); err != nil {
		return err
	}
	s.readPPPoEConfs(cfg)
	s.readL2TPConfs(cfg)
	if err := s.cleanupPPPoE(ctx, pppoeWanted); err != nil {
		return err
	}
	if err := s.cleanupL2TP(ctx, l2tpWanted); err != nil {
		return err
	}
	staticWanted := map[string]bool{}

	for _, w := range cfg.WANs {
		name := ifaceName[w.Interface]
		if name == "" || !linkExists(name) {
			continue
		}
		if !w.Enabled {
			s.stopDHCPClient(ctx, name)
			_, _ = s.Runner.Run(ctx, "ip", "addr", "flush", "dev", name)
			continue
		}

		if _, err := s.Runner.Run(ctx, "ip", "link", "set", name, "up"); err != nil {
			return err
		}
		if w.MTU > 0 {
			_, _ = s.Runner.Run(ctx, "ip", "link", "set", name, "mtu", fmt.Sprint(w.MTU))
		}

		switch w.Proto {
		case "static":
			s.stopDHCPClient(ctx, name)
			if err := s.applyStatic(ctx, w, name); err != nil {
				return err
			}
			if w.Gateway != "" {
				staticWanted[wanRouteKey(w.Gateway, name, w.Metric)] = true
			}
		case "dhcp":
			// Клиент DHCP поднимается отдельным юнитом на интерфейс, чтобы
			// перезапуск netosd не ронял аренду.
			if err := s.ensureDHCPClient(ctx, w, name); err != nil {
				return err
			}
		case "pppoe":
			// Соединение держит pppd: адрес и маршрут по умолчанию приходят
			// от провайдера, поэтому назначать здесь нечего.
			s.stopDHCPClient(ctx, name)
			if err := s.ensurePPPoE(ctx, w, name); err != nil {
				return err
			}
		case "l2tp":
			// Сначала адрес в сети провайдера, и только поверх него туннель:
			// без адреса не найти ни концентратор, ни маршрут до него.
			if w.Underlay == "static" {
				s.stopDHCPClient(ctx, name)
				if err := s.applyStatic(ctx, underlayWAN(w), name); err != nil {
					return err
				}
				if w.Gateway != "" {
					staticWanted[wanRouteKey(w.Gateway, name, underlayMetric(w))] = true
				}
			} else if err := s.ensureDHCPClient(ctx, underlayWAN(w), name); err != nil {
				return err
			}
			if err := s.ensureL2TP(ctx, w, name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("аплинк %s: неизвестный тип подключения %q", w.Name, w.Proto)
		}
	}
	return s.cleanupStaticRoutes(ctx, staticWanted)
}

func (s *WAN) cleanupStaticRoutes(ctx context.Context, wanted map[string]bool) error {
	out, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", "main",
		"proto", fmt.Sprint(config.RouteProto))
	if err != nil {
		return fmt.Errorf("чтение маршрутов аплинков netOS: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		gateway, iface, metric := "", "", 0
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				gateway = fields[i+1]
			case "dev":
				iface = fields[i+1]
			case "metric":
				_, _ = fmt.Sscan(fields[i+1], &metric)
			}
		}
		if wanted[wanRouteKey(gateway, iface, metric)] {
			continue
		}
		args := append([]string{"-4", "route", "del"}, fields...)
		if _, err := s.Runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("удаление старого маршрута аплинка %q: %w", line, err)
		}
	}
	return nil
}

func wanRouteKey(gateway, iface string, metric int) string {
	return fmt.Sprintf("%s|%s|%d", gateway, iface, metric)
}

func (s *WAN) applyStatic(ctx context.Context, w config.WAN, iface string) error {
	current, err := addressesOf(ctx, s.Runner, iface)
	if err != nil {
		return err
	}
	// replace, а не add: адрес с тем же значением мог быть выдан чужим клиентом
	// DHCP и жить с ограниченным сроком. Тогда add молча ничего не делал бы, а
	// netOS считал бы адрес своим статическим — до истечения аренды, после
	// которой аплинк тихо остался бы без адреса. replace делает адрес
	// постоянным и не разрывает установленные соединения.
	if _, err := s.Runner.Run(ctx, "ip", "addr", "replace", w.Address, "dev", iface); err != nil {
		return fmt.Errorf("назначение адреса аплинка %s: %w", w.Address, err)
	}
	for addr := range current {
		if addr != w.Address {
			_, _ = s.Runner.Run(ctx, "ip", "addr", "del", addr, "dev", iface)
		}
	}

	if w.Gateway != "" {
		metric := fmt.Sprint(w.Metric)
		// Маршрут по умолчанию заменяем, а не добавляем: иначе при повторном
		// применении накопится несколько шлюзов с одной метрикой.
		// Метка владельца ставится числом: имя протокола появляется в системе
		// только после того, как подсистема маршрутизации запишет файл, а она
		// выполняется позже — команда с именем просто не прошла бы.
		if _, err := s.Runner.Run(ctx, "ip", "route", "replace", "default",
			"via", w.Gateway, "dev", iface, "metric", metric,
			"proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("маршрут по умолчанию через %s: %w", w.Gateway, err)
		}
	}
	return nil
}

func (s *WAN) ensureDHCPClient(ctx context.Context, w config.WAN, iface string) error {
	unit, err := s.ensureDHCPClientFiles(ctx, w, iface)
	if err != nil {
		return err
	}

	// Уже работающего клиента не трогаем: перезапуск приводит к отпусканию
	// аренды и кратковременной потере аплинка.
	out, err := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if err == nil && strings.TrimSpace(out) == "active" {
		return nil
	}
	if _, err := s.Runner.Run(ctx, "systemctl", "enable", "--now", unit); err != nil {
		return fmt.Errorf("запуск клиента DHCP на %s: %w", iface, err)
	}
	return nil
}

// stopDHCPClient гасит клиента, когда аплинк перевели на статику или выключили.
// Иначе он продолжит переназначать адрес поверх заданного вручную.
func (s *WAN) stopDHCPClient(ctx context.Context, iface string) {
	unit := "netos-dhcp-" + iface + ".service"
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", "--now", unit)
}

func (s *WAN) Health(ctx context.Context, cfg *config.Config) error {
	enabled := false
	for _, w := range cfg.WANs {
		if w.Enabled {
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	// Сессии PPPoE проверяем поимённо: маршрут по умолчанию мог остаться от
	// другого аплинка, и тогда неподнявшийся PPPoE прошёл бы незамеченным.
	for _, w := range cfg.WANs {
		if !w.Enabled || w.Proto != "pppoe" {
			continue
		}
		if err := s.waitPPPoE(ctx, w); err != nil {
			return err
		}
	}

	out, err := s.Runner.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("маршрут по умолчанию отсутствует")
	}
	return nil
}

// ---------------------------------------------------------------------------
// вспомогательное
// ---------------------------------------------------------------------------

// Пути к sysfs и procfs вынесены в переменные, чтобы тесты могли подсунуть
// вместо них каталог с вымышленными интерфейсами: настоящие мосты и VLAN на
// машине разработчика создавать незачем.
var (
	sysClassNet = "/sys/class/net"
	procNetVLAN = "/proc/net/vlan"
)

// linkExists проверяет наличие интерфейса через sysfs — это дешевле запуска ip
// и не требует контекста.
func linkExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := os.Stat(sysClassNet + "/" + name)
	return err == nil
}

func listLinks() ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}

// masterOf возвращает имя бриджа или bond, в который включён порт.
func masterOf(name string) string {
	link, err := os.Readlink(sysClassNet + "/" + name + "/master")
	if err != nil {
		return ""
	}
	parts := strings.Split(link, "/")
	return parts[len(parts)-1]
}

// slavesOf возвращает порты, подчинённые бриджу или агрегации прямо сейчас.
// Список берётся из системы, а не из конфигурации: нас интересует именно то,
// что в конфигурации не описано и подлежит выводу.
func slavesOf(master string) []string {
	entries, err := os.ReadDir(sysClassNet + "/" + master + "/brif")
	if err == nil {
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	names, err := listLinks()
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range names {
		if masterOf(name) == master {
			out = append(out, name)
		}
	}
	return out
}

// linkKind определяет, чем интерфейс является на самом деле: bridge, bond,
// vlan или physical. Пустая строка означает «определить не удалось» — тогда
// выводов о несоответствии не делаем.
func linkKind(name string) string {
	if _, err := os.Stat(sysClassNet + "/" + name + "/bridge"); err == nil {
		return "bridge"
	}
	if _, err := os.Stat(sysClassNet + "/" + name + "/bonding"); err == nil {
		return "bond"
	}
	if _, err := os.Stat(procNetVLAN + "/" + name); err == nil {
		return "vlan"
	}
	if _, err := os.Stat(sysClassNet + "/" + name + "/device"); err == nil {
		return "physical"
	}
	return ""
}

// vlanOf возвращает номер и родителя существующего VLAN. Данные берутся из
// /proc/net/vlan, который создаёт модуль 8021q; строки там выглядят так:
//
//	eth0.100  VID: 100	 REORDER_HDR: 1  dev->priv_flags: 1
//	Device: eth0
func vlanOf(name string) (id int, parent string, ok bool) {
	data, err := os.ReadFile(procNetVLAN + "/" + name)
	if err != nil {
		return 0, "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "VID:":
				_, _ = fmt.Sscan(fields[i+1], &id)
			case "Device:":
				parent = fields[i+1]
			}
		}
	}
	return id, parent, id > 0
}

// describeMismatch объясняет, чем существующий интерфейс отличается от
// описанного в конфигурации. Пустая строка означает, что различий нет.
//
// Без этой проверки смена номера VLAN или его родителя в панели не доходила до
// системы: интерфейс с нужным именем уже был, и его молча оставляли как есть.
// Администратор видел в панели одно, а в ip a — другое.
func describeMismatch(cfg *config.Config, iface config.Interface) string {
	if iface.Type == "physical" {
		return ""
	}
	kind := linkKind(iface.Name)
	if kind == "" {
		return "" // определить не удалось — не выдумываем
	}
	if kind != iface.Type {
		return fmt.Sprintf("это %s, а не %s", kind, iface.Type)
	}
	if iface.Type != "vlan" {
		return ""
	}
	id, parent, ok := vlanOf(iface.Name)
	if !ok {
		return ""
	}
	if id != iface.VLANID {
		return fmt.Sprintf("номер VLAN %d вместо %d", id, iface.VLANID)
	}
	if want := cfg.InterfaceName(iface.Parent); want != "" && parent != want {
		return fmt.Sprintf("поднят над %s вместо %s", parent, want)
	}
	return ""
}

// isLegacyManagedName сообщает, похоже ли имя на созданное netOS прежних
// версий, когда владение определялось префиксом. Ныне владение хранится в
// OwnedPath; шаблон остался только чтобы убрать за старой установкой.
func isLegacyManagedName(name string) bool {
	// Только типы, которыми владеет подсистема Interfaces. Каналы и VPN-
	// серверы имеют отдельные реестры владения и сами отвечают за wg-ch*,
	// tun-ch* и wg-srv*; удалять их отсюда нельзя даже во время миграции.
	for _, prefix := range []string{"br-", "vl-", "bond-", "d-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// addressesOf возвращает адреса IPv4, назначенные интерфейсу.
func addressesOf(ctx context.Context, r system.Runner, iface string) (map[string]bool, error) {
	out, err := r.Run(ctx, "ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				result[fields[i+1]] = true
			}
		}
	}
	return result, nil
}

func describeInterface(cfg *config.Config, i config.Interface) string {
	switch i.Type {
	case "vlan":
		parent := cfg.InterfaceName(i.Parent)
		if parent == "" {
			parent = "(не выбран)"
		}
		return fmt.Sprintf("VLAN %d на %s", i.VLANID, parent)
	case "bridge":
		return "бридж: " + strings.Join(cfg.InterfaceNames(i.Members), ", ")
	case "bond":
		return "агрегация: " + strings.Join(cfg.InterfaceNames(i.Members), ", ")
	}
	return i.Type
}
