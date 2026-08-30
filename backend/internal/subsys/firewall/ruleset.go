// Package firewall собирает набор правил iptables из конфигурации и применяет
// его одним вызовом iptables-restore.
//
// Устройство подчинено одному требованию: вывод iptables-save должен читаться
// без сверки с панелью, потому что читать его приходится в самый неудачный
// момент.
//
//   - Цепочка называется по зоне и направлению: WAN-IN, LAN-FWD, VPN-OUT.
//     Из имени сразу понятно, какой трафик внутри, и не нужно выяснять, что
//     означает очередной netos-чего-то-там.
//   - Цепочка создаётся, только если в её зоне есть хотя бы один интерфейс, и
//     сразу получает переход из своей встроенной цепочки. Объявленных цепочек,
//     в которые ниоткуда нет входа, не бывает.
//   - Каждое правило в ядре соответствует правилу в конфигурации. netOS не
//     добавляет ничего от себя: что администратор видит в панели, то и работает.
package firewall

import (
	"fmt"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/multiwan"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
)

// Ruleset — сгенерированный набор правил.
type Ruleset struct {
	IPv4 string
	IPv6 string
}

type zoneMap map[string][]string

// hook связывает направление с встроенной цепочкой и суффиксом имени.
type hook struct {
	flow    string // in | out | forward
	builtin string // INPUT | OUTPUT | FORWARD
	suffix  string // IN | OUT | FWD
	// selector — по какому интерфейсу зона определяется в этой цепочке.
	selector string // -i | -o
}

var hooks = []hook{
	{flow: "in", builtin: "INPUT", suffix: "IN", selector: "-i"},
	{flow: "forward", builtin: "FORWARD", suffix: "FWD", selector: "-i"},
	{flow: "out", builtin: "OUTPUT", suffix: "OUT", selector: "-o"},
}

func Build(cfg *config.Config) (*Ruleset, error) {
	zones := buildZoneMap(cfg)

	var b builder
	b.mangle(cfg, zones)
	b.nat(cfg, zones)
	b.filter(cfg, zones)

	return &Ruleset{IPv4: b.String(), IPv6: buildIPv6(cfg)}, nil
}

// buildZoneMap раскладывает интерфейсы по зонам.
func buildZoneMap(cfg *config.Config) zoneMap {
	byID := map[string]string{}
	for _, iface := range cfg.Interfaces {
		byID[iface.ID] = iface.Name
	}

	zm := zoneMap{}
	add := func(zone, iface string) {
		if zone == "" || iface == "" {
			return
		}
		for _, existing := range zm[zone] {
			if existing == iface {
				return
			}
		}
		zm[zone] = append(zm[zone], iface)
	}

	for _, n := range cfg.Networks {
		if n.Enabled {
			add(n.Zone, byID[n.Interface])
		}
	}
	for _, w := range cfg.WANs {
		if !w.Enabled {
			continue
		}
		name := byID[w.Interface]
		if w.Proto == "pppoe" || w.Proto == "l2tp" {
			name = "ppp-" + w.ID
		}
		add("wan", name)
	}
	for _, ch := range cfg.Channels {
		if ch.Enabled && ch.Type != "direct" {
			add("vpn", channelInterface(ch))
		}
	}
	for _, s := range cfg.VPNServers {
		if s.Enabled {
			add("vpn", serverInterface(s))
		}
	}

	for zone := range zm {
		sort.Strings(zm[zone])
	}
	return zm
}

func channelInterface(ch config.Channel) string {
	switch ch.Type {
	case "wireguard":
		return fmt.Sprintf("wg-ch%d", ch.Index)
	case "l2tp":
		return fmt.Sprintf("ppp-ch%d", ch.Index)
	case "ikev2":
		return fmt.Sprintf("xfrm-ch%d", ch.Index)
	case "xray", "openconnect":
		return fmt.Sprintf("tun-ch%d", ch.Index)
	}
	return ""
}

func serverInterface(s config.VPNServer) string {
	switch s.Type {
	case "wireguard":
		return fmt.Sprintf("wg-srv%d", s.Index)
	case "ocserv":
		return fmt.Sprintf("vpns%d", s.Index)
	case "ikev2":
		return fmt.Sprintf("xfrm-srv%d", s.Index)
	}
	return ""
}

type builder struct{ sb strings.Builder }

func (b *builder) String() string { return b.sb.String() }

func (b *builder) line(format string, args ...any) {
	fmt.Fprintf(&b.sb, format+"\n", args...)
}

// ChainName возвращает имя цепочки для зоны и направления: WAN-IN, LAN-FWD.
func ChainName(zone, suffix string) string {
	return strings.ToUpper(zone) + "-" + suffix
}

// ExpectedChains перечисляет цепочки, которые должны появиться в ядре при
// текущей конфигурации. Используется проверкой после применения: требовать
// цепочку для зоны без интерфейсов нельзя — генератор её и не создаёт.
func ExpectedChains(cfg *config.Config) []string {
	if !cfg.Firewall.Enabled {
		return nil
	}
	zones := buildZoneMap(cfg)
	var out []string
	for _, z := range cfg.Firewall.Zones {
		if len(zones[z.Name]) == 0 {
			continue
		}
		for _, h := range hooks {
			out = append(out, ChainName(z.Name, h.suffix))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// filter
// ---------------------------------------------------------------------------

func (b *builder) filter(cfg *config.Config, zones zoneMap) {
	b.line("*filter")

	if !cfg.Firewall.Enabled {
		// Выключенный файрволл — честно открытый роутер, а не «оставить как
		// было»: иначе старые правила продолжат резать трафик, а панель будет
		// показывать, что фильтрации нет.
		b.line(":INPUT ACCEPT [0:0]")
		b.line(":FORWARD ACCEPT [0:0]")
		b.line(":OUTPUT ACCEPT [0:0]")
		b.line("COMMIT")
		return
	}

	outputPolicy := cfg.Firewall.OutputPolicy
	if outputPolicy == "" {
		outputPolicy = "accept"
	}

	b.line(":INPUT DROP [0:0]")
	b.line(":FORWARD DROP [0:0]")
	b.line(":OUTPUT %s [0:0]", strings.ToUpper(target(outputPolicy)))

	// Объявляем только те цепочки, для которых есть интерфейсы: цепочка без
	// входа — мусор, который сбивает с толку при разборе.
	type liveChain struct {
		zone  config.Zone
		hook  hook
		chain string
	}
	var chains []liveChain

	for _, z := range cfg.Firewall.Zones {
		if len(zones[z.Name]) == 0 {
			continue
		}
		for _, h := range hooks {
			chains = append(chains, liveChain{zone: z, hook: h, chain: ChainName(z.Name, h.suffix)})
		}
	}
	for _, c := range chains {
		b.line(":%s - [0:0]", c.chain)
	}

	// Заблокированный клиент не должен сохранить доступ по уже установленному
	// соединению или обойти запрет статическим IP. Поэтому эти правила стоят
	// раньше системного ESTABLISHED и дополняют отказ DHCP-сервера в аренде.
	b.blockedClients(cfg)

	// 1. Правила без привязки к зоне — прямо во встроенных цепочках.
	b.line("# --- правила без привязки к зоне ---")
	for _, h := range hooks {
		for _, r := range cfg.Firewall.Rules {
			if !r.Enabled || r.Zone != "global" {
				continue
			}
			if r.Flow != h.flow && r.Flow != "any" {
				continue
			}
			b.emitRule(h.builtin, r, "")
		}
	}

	// 2. Разбор по зонам: переход в цепочку по интерфейсу.
	b.line("# --- разбор по зонам ---")
	for _, c := range chains {
		for _, iface := range zones[c.zone.Name] {
			b.line("-A %s %s %s -j %s", c.hook.builtin, c.hook.selector, iface, c.chain)
		}
	}

	// 3. Содержимое цепочек.
	for _, c := range chains {
		b.line("# --- %s: %s ---", c.chain, describeChain(c.zone, c.hook))

		if c.hook.flow == "forward" && c.zone.Name == "lan" {
			b.isolation(cfg, c.chain)
		}

		for _, r := range cfg.Firewall.Rules {
			if !r.Enabled || r.Zone != c.zone.Name {
				continue
			}
			if r.Flow != c.hook.flow {
				continue
			}
			// Зона назначения разворачивается в выходные интерфейсы, поэтому
			// одно правило панели может дать несколько строк в ядре.
			if c.hook.flow == "forward" && r.DstZone != "" {
				for _, out := range zones[r.DstZone] {
					b.emitRule(c.chain, r, " -o "+out)
				}
				continue
			}
			b.emitRule(c.chain, r, "")
		}

		// Проброшенные порты: без разрешения в форварде трансляция сработает,
		// а пакет всё равно не дойдёт.
		if c.hook.flow == "forward" && c.zone.Name == "wan" {
			b.portForwardAccept(cfg, c.chain)
		}
		if c.hook.flow == "in" && c.zone.Name == "wan" {
			b.vpnServerAccept(cfg, c.chain)
		}

		// Политика зоны завершает вход и форвард. Для исхода политика общая и
		// задана в самой цепочке OUTPUT, поэтому здесь просто возвращаемся.
		if c.hook.flow == "out" {
			b.line("-A %s -j RETURN", c.chain)
		} else {
			b.line("-A %s -m comment --comment %q -j %s",
				c.chain, "политика зоны", target(c.zone.Policy))
		}
	}

	b.line("COMMIT")
}

func (b *builder) vpnServerAccept(cfg *config.Config, chain string) {
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "wireguard" {
			continue
		}
		b.line("-A %s -p udp --dport %d -m comment --comment %q -j ACCEPT",
			chain, server.Port, truncate("VPN-сервер «"+server.Name+"»", 240))
	}
}

func (b *builder) blockedClients(cfg *config.Config) {
	type blockedClient struct {
		mac  string
		name string
	}
	var clients []blockedClient
	for _, client := range cfg.Clients {
		if client.Blocked && client.MAC != "" {
			clients = append(clients, blockedClient{mac: strings.ToLower(client.MAC), name: client.Name})
		}
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].mac < clients[j].mac })
	if len(clients) == 0 {
		return
	}
	b.line("# --- заблокированные клиенты ---")
	for _, client := range clients {
		comment := "заблокирован клиент " + client.mac
		if client.name != "" {
			comment = "заблокирован клиент " + client.name
		}
		for _, chain := range []string{"INPUT", "FORWARD"} {
			b.line("-A %s -m mac --mac-source %s -m comment --comment %q -j DROP",
				chain, client.mac, truncate(comment, 240))
		}
	}

}

// emitRule печатает одну строку правила.
func (b *builder) emitRule(chain string, r config.FirewallRule, extra string) {
	sel := extra + selectors(r)
	if r.Log {
		b.line("-A %s%s -j LOG --log-prefix %q --log-level 4", chain, sel, "netos "+r.Name+": ")
	}
	b.line("-A %s%s -j %s", chain, sel, target(r.Action))
}

// portForwardAccept разрешает транзит уже перенаправленных пакетов.
//
// Без этого трансляция сработает, а пакет всё равно не дойдёт: классическая
// ловушка ручной настройки, на которой спотыкаются все.
func (b *builder) portForwardAccept(cfg *config.Config, chain string) {
	for _, n := range cfg.Firewall.NAT {
		if !n.Enabled || n.Direction != "destination" {
			continue
		}
		for _, proto := range protocols(n.Protocol) {
			port := n.DestPort
			if port == "" {
				port = iptablesPortSpec(n.ExtPort)
			}
			b.line("-A %s -d %s -p %s --dport %s -m conntrack --ctstate DNAT -m comment --comment %q -j ACCEPT",
				chain, n.DestIP, proto, port, "проброс: "+n.Name)
		}
	}
}

func (b *builder) isolation(cfg *config.Config, chain string) {
	for _, a := range cfg.Networks {
		if !a.Enabled || !a.Isolated {
			continue
		}
		for _, other := range cfg.Networks {
			if !other.Enabled || other.ID == a.ID {
				continue
			}
			b.line("-A %s -s %s -d %s -m comment --comment %q -j REJECT --reject-with icmp-port-unreachable",
				chain, subnetOf(a.RouterAddress), subnetOf(other.RouterAddress),
				"изоляция: "+a.Name)
		}
	}
}

// describeChain даёт человекочитаемое пояснение к заголовку цепочки.
func describeChain(z config.Zone, h hook) string {
	switch h.flow {
	case "in":
		return "трафик из зоны «" + z.Title + "» к самому роутеру"
	case "out":
		return "трафик самого роутера в зону «" + z.Title + "»"
	default:
		return "транзитный трафик из зоны «" + z.Title + "»"
	}
}

func selectors(r config.FirewallRule) string {
	var s strings.Builder

	if r.Interface != "" {
		fmt.Fprintf(&s, " -i %s", r.Interface)
	}
	if r.Protocol != "" && r.Protocol != "any" {
		fmt.Fprintf(&s, " -p %s", r.Protocol)
	}
	if r.SrcIP != "" {
		fmt.Fprintf(&s, " -s %s", r.SrcIP)
	}
	if r.DstIP != "" {
		fmt.Fprintf(&s, " -d %s", r.DstIP)
	}
	if r.SrcMAC != "" {
		fmt.Fprintf(&s, " -m mac --mac-source %s", r.SrcMAC)
	}
	if r.SrcPort != "" {
		fmt.Fprintf(&s, " -m multiport --sports %s", iptablesPortSpec(r.SrcPort))
	}
	if r.DstPort != "" {
		fmt.Fprintf(&s, " -m multiport --dports %s", iptablesPortSpec(r.DstPort))
	}
	if r.ConnState != "" {
		fmt.Fprintf(&s, " -m conntrack --ctstate %s", strings.ToUpper(r.ConnState))
	}
	if r.Schedule != nil {
		s.WriteString(scheduleMatch(*r.Schedule))
	}
	if r.Name != "" {
		fmt.Fprintf(&s, " -m comment --comment %q", truncate(r.Name, 240))
	}
	return s.String()
}

func scheduleMatch(s config.Schedule) string {
	var b strings.Builder
	b.WriteString(" -m time")
	if s.TimeStart != "" {
		fmt.Fprintf(&b, " --timestart %s", s.TimeStart)
	}
	if s.TimeStop != "" {
		fmt.Fprintf(&b, " --timestop %s", s.TimeStop)
	}
	if len(s.Days) > 0 {
		fmt.Fprintf(&b, " --weekdays %s", strings.Join(s.Days, ","))
	}
	b.WriteString(" --kerneltz")
	return b.String()
}

// ---------------------------------------------------------------------------
// nat
// ---------------------------------------------------------------------------

func (b *builder) nat(cfg *config.Config, zones zoneMap) {
	b.line("*nat")
	b.line(":PREROUTING ACCEPT [0:0]")
	b.line(":INPUT ACCEPT [0:0]")
	b.line(":OUTPUT ACCEPT [0:0]")
	b.line(":POSTROUTING ACCEPT [0:0]")
	if cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		for _, wan := range cfg.WANs {
			if wan.Enabled {
				b.line("-A POSTROUTING -o %s -m comment --comment %q -j MASQUERADE", wanInterface(cfg, wan), "NAT аплинка «"+wan.Name+"»")
			}
		}
	}
	for _, ch := range cfg.Channels {
		if ch.Enabled && (ch.Type == "wireguard" || ch.Type == "openconnect") {
			b.line("-A POSTROUTING -o %s -m comment --comment %q -j MASQUERADE",
				channels.InterfaceName(ch), "NAT канала «"+ch.Name+"»")
		}
	}

	if cfg.DNS.Enabled && cfg.DNS.ForceLocal {
		for _, n := range cfg.Networks {
			if !n.Enabled {
				continue
			}
			routerIP := addressOf(n.RouterAddress)
			for _, proto := range []string{"udp", "tcp"} {
				b.line("-A PREROUTING -s %s -p %s --dport 53 ! -d %s -m comment --comment %q -j DNAT --to-destination %s:%d",
					subnetOf(n.RouterAddress), proto, routerIP, "перехват DNS", routerIP, cfg.DNS.Port)
			}
		}
	}

	for _, n := range cfg.Firewall.NAT {
		if !n.Enabled {
			continue
		}
		if n.Direction == "destination" {
			b.natDestination(n)
			continue
		}
		b.natSource(n)
	}

	b.line("COMMIT")
	_ = zones
}

// natSource — подмена адреса отправителя на выходе.
func (b *builder) natSource(n config.NATRule) {
	if n.Interface == "" {
		return
	}
	var sel strings.Builder
	fmt.Fprintf(&sel, " -o %s", n.Interface)
	if n.Source != "" {
		fmt.Fprintf(&sel, " -s %s", n.Source)
	}
	fmt.Fprintf(&sel, " -m comment --comment %q", truncate(n.Name, 240))

	if n.ToSource != "" {
		b.line("-A POSTROUTING%s -j SNAT --to-source %s", sel.String(), n.ToSource)
		return
	}
	// Без указанного адреса подставится текущий адрес интерфейса — то, что
	// нужно на подключении с меняющимся адресом.
	b.line("-A POSTROUTING%s -j MASQUERADE", sel.String())
}

// natDestination — проброс обращения снаружи внутрь сети.
func (b *builder) natDestination(n config.NATRule) {
	if n.DestIP == "" || n.ExtPort == "" {
		return
	}
	for _, proto := range protocols(n.Protocol) {
		var sel strings.Builder
		if n.Interface != "" {
			fmt.Fprintf(&sel, " -i %s", n.Interface)
		}
		if n.AllowFrom != "" {
			fmt.Fprintf(&sel, " -s %s", n.AllowFrom)
		}
		dest := n.DestIP
		if n.DestPort != "" {
			dest = n.DestIP + ":" + n.DestPort
		}
		b.line("-A PREROUTING%s -p %s --dport %s -m comment --comment %q -j DNAT --to-destination %s",
			sel.String(), proto, iptablesPortSpec(n.ExtPort), truncate(n.Name, 240), dest)
	}
}

// ---------------------------------------------------------------------------
// mangle
// ---------------------------------------------------------------------------

func (b *builder) mangle(cfg *config.Config, zones zoneMap) {
	b.line("*mangle")
	b.line(":PREROUTING ACCEPT [0:0]")
	b.line(":INPUT ACCEPT [0:0]")
	b.line(":FORWARD ACCEPT [0:0]")
	b.line(":OUTPUT ACCEPT [0:0]")
	b.line(":POSTROUTING ACCEPT [0:0]")

	b.channelPolicies(cfg)
	b.dnsChannelPolicies(cfg)
	b.multiWANPolicies(cfg)

	for _, z := range cfg.Firewall.Zones {
		if !z.MSSClamp {
			continue
		}
		for _, iface := range zones[z.Name] {
			b.line("-A FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -m comment --comment %q -j TCPMSS --clamp-mss-to-pmtu",
				iface, "подгонка размера пакетов")
		}
	}

	b.line("COMMIT")
}

func (b *builder) dnsChannelPolicies(cfg *config.Config) {
	channelByID := map[string]config.Channel{}
	for _, ch := range cfg.Channels {
		channelByID[ch.ID] = ch
	}
	bindings := cfg.DNSChannelBindings()
	if len(bindings) == 0 {
		return
	}
	b.line("-A OUTPUT -j CONNMARK --restore-mark")
	for _, binding := range bindings {
		ch, ok := channelByID[binding.ChannelID]
		if !ok || !ch.Enabled || (ch.Type != "wireguard" && ch.Type != "openconnect") {
			continue
		}
		mark := fmt.Sprintf("0x%x", channels.Mark(ch))
		comment := fmt.Sprintf("DNS %s через %s", binding.UpstreamID, ch.Name)
		b.line("-A OUTPUT -m mark --mark 0 -d %s -p %s --dport %d -m comment --comment %q -j MARK --set-mark %s", binding.Address, binding.Protocol, binding.Port, truncate(comment, 240), mark)
		b.line("-A OUTPUT -m mark --mark %s -d %s -p %s --dport %d -j CONNMARK --save-mark", mark, binding.Address, binding.Protocol, binding.Port)
	}
}

func (b *builder) multiWANPolicies(cfg *config.Config) {
	if !cfg.MultiWAN.Enabled || cfg.MultiWAN.Mode != "balance" {
		return
	}
	var wans []config.WAN
	total := 0
	for _, wan := range cfg.WANs {
		if wan.Enabled {
			wans = append(wans, wan)
			total += wan.Weight
		}
	}
	if len(wans) < 2 || total <= 0 {
		return
	}
	b.line(":NETOS-MULTIWAN - [0:0]")
	b.line("-A PREROUTING -j CONNMARK --restore-mark")
	b.line("-A PREROUTING -m mark --mark 0 -j NETOS-MULTIWAN")
	remaining := total
	for i, wan := range wans {
		mark := fmt.Sprintf("0x%x", multiwan.Mark(wan))
		if i == len(wans)-1 {
			b.line("-A NETOS-MULTIWAN -j MARK --set-mark %s", mark)
		} else {
			probability := float64(wan.Weight) / float64(remaining)
			b.line("-A NETOS-MULTIWAN -m statistic --mode random --probability %.6f -j MARK --set-mark %s", probability, mark)
		}
		b.line("-A NETOS-MULTIWAN -m mark --mark %s -j CONNMARK --save-mark", mark)
		b.line("-A NETOS-MULTIWAN -m mark --mark %s -j RETURN", mark)
		remaining -= wan.Weight
	}
}

func wanInterface(cfg *config.Config, wan config.WAN) string {
	if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
		return "ppp-" + wan.ID
	}
	return cfg.InterfaceName(wan.Interface)
}

// channelPolicies присваивает новым соединениям fwmark канала, а следующим
// пакетам того же соединения восстанавливает его из conntrack. Явные политики
// имеют приоритет над настройкой клиента, а клиент — над настройкой сегмента.
func (b *builder) channelPolicies(cfg *config.Config) {
	channelByID := map[string]config.Channel{}
	for _, ch := range cfg.Channels {
		channelByID[ch.ID] = ch
	}

	type policyRule struct {
		priority int
		id       string
		match    string
		channel  string
		comment  string
	}
	var rules []policyRule
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		rules = append(rules, policyRule{
			priority: p.Priority, id: p.ID, match: policySelectors(cfg, p),
			channel: p.Channel, comment: p.Name,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].priority != rules[j].priority {
			return rules[i].priority < rules[j].priority
		}
		return rules[i].id < rules[j].id
	})

	clients := append([]config.Client(nil), cfg.Clients...)
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	for _, client := range clients {
		if client.Blocked || client.Channel == "" || client.Channel == "direct" {
			continue
		}
		rules = append(rules, policyRule{
			priority: 1_000_000, id: client.ID,
			match:   " -m mac --mac-source " + strings.ToLower(client.MAC),
			channel: client.Channel, comment: "канал клиента «" + client.Name + "»",
		})
	}

	servers := append([]config.VPNServer(nil), cfg.VPNServers...)
	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	for _, server := range servers {
		if !server.Enabled || server.Type != "wireguard" {
			continue
		}
		peers := append([]config.VPNPeer(nil), server.Peers...)
		sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
		for _, peer := range peers {
			if !peer.Enabled || peer.Channel == "" || peer.Channel == "direct" {
				continue
			}
			rules = append(rules, policyRule{
				priority: 1_500_000, id: server.ID + "/" + peer.ID,
				match: " -i " + vpnservers.InterfaceName(server) + " -s " + peer.Address + "/32", channel: peer.Channel,
				comment: "канал VPN-пира «" + peer.Name + "»",
			})
		}
		if server.DefaultChannel != "" && server.DefaultChannel != "direct" {
			rules = append(rules, policyRule{
				priority: 1_600_000, id: server.ID, match: " -i " + vpnservers.InterfaceName(server),
				channel: server.DefaultChannel, comment: "канал VPN-сервера «" + server.Name + "»",
			})
		}
	}

	networks := append([]config.Network(nil), cfg.Networks...)
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })
	for _, network := range networks {
		if !network.Enabled || network.DefaultChannel == "" || network.DefaultChannel == "direct" {
			continue
		}
		rules = append(rules, policyRule{
			priority: 2_000_000, id: network.ID,
			match:   " -s " + subnetOf(network.RouterAddress),
			channel: network.DefaultChannel, comment: "канал сегмента «" + network.Name + "»",
		})
	}
	if len(rules) == 0 {
		return
	}

	b.line(":NETOS-POLICY - [0:0]")
	b.line("-A PREROUTING -j CONNMARK --restore-mark")
	b.line("-A PREROUTING -m mark --mark 0 -j NETOS-POLICY")
	for _, rule := range rules {
		if rule.channel == "" || rule.channel == "direct" {
			b.line("-A NETOS-POLICY%s -m comment --comment %q -j RETURN", rule.match, truncate(rule.comment, 240))
			continue
		}
		ch, ok := channelByID[rule.channel]
		if !ok || !ch.Enabled || (ch.Type != "wireguard" && ch.Type != "openconnect") {
			continue // валидатор не разрешает применить такую конфигурацию
		}
		mark := fmt.Sprintf("0x%x", channels.Mark(ch))
		b.line("-A NETOS-POLICY%s -m comment --comment %q -j MARK --set-mark %s", rule.match, truncate(rule.comment, 240), mark)
		b.line("-A NETOS-POLICY -m mark --mark %s -j CONNMARK --save-mark", mark)
		b.line("-A NETOS-POLICY -m mark --mark %s -j RETURN", mark)
	}
}

func policySelectors(cfg *config.Config, p config.Policy) string {
	var s strings.Builder
	if p.VPNServer != "" {
		for _, server := range cfg.VPNServers {
			if server.ID != p.VPNServer {
				continue
			}
			fmt.Fprintf(&s, " -i %s", vpnservers.InterfaceName(server))
			if p.VPNPeer != "" {
				for _, peer := range server.Peers {
					if peer.ID == p.VPNPeer {
						fmt.Fprintf(&s, " -s %s/32", peer.Address)
						break
					}
				}
			}
			break
		}
	}
	if p.Network != "" {
		for _, network := range cfg.Networks {
			if network.ID == p.Network {
				fmt.Fprintf(&s, " -s %s", subnetOf(network.RouterAddress))
				break
			}
		}
	}
	if p.SrcIP != "" {
		fmt.Fprintf(&s, " -s %s", p.SrcIP)
	}
	if p.SrcMAC != "" {
		fmt.Fprintf(&s, " -m mac --mac-source %s", strings.ToLower(p.SrcMAC))
	}
	if p.Protocol != "" && p.Protocol != "any" {
		fmt.Fprintf(&s, " -p %s", p.Protocol)
	}
	if p.DstIP != "" {
		fmt.Fprintf(&s, " -d %s", p.DstIP)
	}
	if p.DstPort != "" {
		fmt.Fprintf(&s, " -m multiport --dports %s", iptablesPortSpec(p.DstPort))
	}
	if p.Schedule != nil {
		s.WriteString(scheduleMatch(*p.Schedule))
	}
	return s.String()
}

// В JSON диапазоны пишутся привычно как 8000-8010, а iptables в match
// ожидает двоеточие: 8000:8010. Для --to-destination исходная запись
// сохраняется, поскольку там синтаксис другой.
func iptablesPortSpec(spec string) string {
	return strings.ReplaceAll(spec, "-", ":")
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

func buildIPv6(cfg *config.Config) string {
	var b builder
	b.line("*filter")
	if cfg.IPv6.Mode != "off" {
		// Даже разрешающий ruleset нужно применить: ip6tables-restore тем самым
		// снимает DROP, оставшийся от предыдущего режима off.
		b.line(":INPUT ACCEPT [0:0]")
		b.line(":FORWARD ACCEPT [0:0]")
		b.line(":OUTPUT ACCEPT [0:0]")
		b.line("COMMIT")
		return b.String()
	}
	b.line(":INPUT DROP [0:0]")
	b.line(":FORWARD DROP [0:0]")
	b.line(":OUTPUT DROP [0:0]")
	b.line("# Локальная петля остаётся: часть системного софта ходит на ::1.")
	b.line("-A INPUT -i lo -j ACCEPT")
	b.line("-A OUTPUT -o lo -j ACCEPT")
	b.line("COMMIT")
	return b.String()
}

// ---------------------------------------------------------------------------

func target(action string) string {
	switch action {
	case "accept":
		return "ACCEPT"
	case "reject":
		return "REJECT --reject-with icmp-port-unreachable"
	case "continue":
		return "RETURN"
	default:
		return "DROP"
	}
}

func protocols(spec string) []string {
	if spec == "tcpudp" {
		return []string{"tcp", "udp"}
	}
	return []string{spec}
}

func addressOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

func subnetOf(cidr string) string {
	addr, maskStr, ok := strings.Cut(cidr, "/")
	if !ok {
		return cidr
	}
	var o [4]int
	if n, _ := fmt.Sscanf(addr, "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3]); n != 4 {
		return cidr
	}
	var bits int
	if _, err := fmt.Sscanf(maskStr, "%d", &bits); err != nil || bits < 0 || bits > 32 {
		return cidr
	}
	value := uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3])
	mask := uint32(0xffffffff) << (32 - bits)
	if bits == 0 {
		mask = 0
	}
	n := value & mask
	return fmt.Sprintf("%d.%d.%d.%d/%d", n>>24&0xff, n>>16&0xff, n>>8&0xff, n&0xff, bits)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
