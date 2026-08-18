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
			if r.Flow != c.hook.flow && r.Flow != "any" {
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

// emitRule печатает одну строку правила.
func (b *builder) emitRule(chain string, r config.FirewallRule, extra string) {
	sel := extra + selectors(r)
	if r.Log {
		b.line("-A %s%s -j LOG --log-prefix %q --log-level 4", chain, sel, "netos "+r.Name+": ")
	}
	b.line("-A %s%s -j %s", chain, sel, target(r.Action))
}

func (b *builder) portForwardAccept(cfg *config.Config, chain string) {
	for _, pf := range cfg.Firewall.PortForwards {
		if !pf.Enabled {
			continue
		}
		for _, proto := range protocols(pf.Protocol) {
			port := pf.DestPort
			if port == "" {
				port = pf.ExtPort
			}
			b.line("-A %s -d %s -p %s --dport %s -m conntrack --ctstate DNAT -m comment --comment %q -j ACCEPT",
				chain, pf.DestIP, proto, port, "проброс: "+pf.Name)
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
		fmt.Fprintf(&s, " -m multiport --sports %s", r.SrcPort)
	}
	if r.DstPort != "" {
		fmt.Fprintf(&s, " -m multiport --dports %s", r.DstPort)
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

	for _, pf := range cfg.Firewall.PortForwards {
		if !pf.Enabled {
			continue
		}
		inIfaces := zones["wan"]
		if pf.WAN != "" {
			if iface := wanInterface(cfg, pf.WAN); iface != "" {
				inIfaces = []string{iface}
			}
		}
		for _, iface := range inIfaces {
			for _, proto := range protocols(pf.Protocol) {
				var sel strings.Builder
				fmt.Fprintf(&sel, " -i %s", iface)
				if pf.SrcRestrict != "" {
					fmt.Fprintf(&sel, " -s %s", pf.SrcRestrict)
				}
				dest := pf.DestIP
				if pf.DestPort != "" {
					dest = pf.DestIP + ":" + pf.DestPort
				}
				b.line("-A PREROUTING%s -p %s --dport %s -m comment --comment %q -j DNAT --to-destination %s",
					sel.String(), proto, pf.ExtPort, "проброс: "+pf.Name, dest)
			}
		}
	}

	for _, n := range cfg.Firewall.NAT {
		if !n.Enabled {
			continue
		}
		outIfaces := []string{}
		if n.OutInterface != "" {
			outIfaces = []string{n.OutInterface}
		} else if n.OutZone != "" {
			outIfaces = append(outIfaces, zones[n.OutZone]...)
		}
		for _, iface := range outIfaces {
			var sel strings.Builder
			fmt.Fprintf(&sel, " -o %s", iface)
			if n.SrcIP != "" {
				fmt.Fprintf(&sel, " -s %s", n.SrcIP)
			}
			fmt.Fprintf(&sel, " -m comment --comment %q", truncate(n.Name, 240))

			if n.Type == "snat" && n.ToSource != "" {
				b.line("-A POSTROUTING%s -j SNAT --to-source %s", sel.String(), n.ToSource)
			} else {
				b.line("-A POSTROUTING%s -j MASQUERADE", sel.String())
			}
		}
	}

	b.line("COMMIT")
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

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

func buildIPv6(cfg *config.Config) string {
	if cfg.IPv6.Mode != "off" {
		return ""
	}
	var b builder
	b.line("*filter")
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

func wanInterface(cfg *config.Config, wanID string) string {
	for _, w := range cfg.WANs {
		if w.ID != wanID {
			continue
		}
		if w.Proto == "pppoe" || w.Proto == "l2tp" {
			return "ppp-" + w.ID
		}
		for _, i := range cfg.Interfaces {
			if i.ID == w.Interface {
				return i.Name
			}
		}
	}
	return ""
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
