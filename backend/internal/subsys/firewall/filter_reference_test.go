package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
)

// Snapshot before zone-rule indexing; retained as an independent ordering oracle.
func (b *builder) filterScanReference(cfg *config.Config, zones zoneMap) {
	b.line("*filter")

	if !cfg.Firewall.Enabled {
		// Выключенный файрволл — честно открытый роутер, а не «оставить как
		// было»: иначе старые правила продолжат резать трафик, а панель будет
		// показывать, что фильтрации нет.
		b.line(":INPUT ACCEPT [0:0]")
		b.line(":FORWARD ACCEPT [0:0]")
		b.line(":OUTPUT ACCEPT [0:0]")
		b.internetBlockedClients(cfg, false)
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
	chains := liveChains(cfg, zones)
	targets := map[string]bool{}
	for _, c := range chains {
		targets[c.chain] = true
		b.line(":%s - [0:0]", c.chain)
	}

	// Заблокированный клиент не должен сохранить доступ по уже установленному
	// соединению или обойти запрет статическим IP. Поэтому эти правила стоят
	// раньше системного ESTABLISHED и дополняют отказ DHCP-сервера в аренде.
	b.isolation(cfg)
	b.blockedClients(cfg)
	b.internetBlockedClients(cfg, false)
	b.sambaAccess(cfg)
	b.socksAccess(cfg)

	// 1. Правила без привязки к зоне — прямо во встроенных цепочках.
	b.line("# --- правила без привязки к зоне ---")
	if cfg.UsesACME() {
		// HTTP-01 проверяет домен с непредсказуемых адресов CA. На этом порту
		// панель не обслуживается: handler отвечает на challenge и перенаправляет
		// навигацию на HTTPS; API и вход по HTTP недоступны.
		b.line("-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment %q -j ACCEPT", "ACME HTTP-01")
	}
	for _, h := range hooks {
		for _, r := range cfg.Firewall.Rules {
			if !r.Enabled || r.Zone != "global" {
				continue
			}
			if r.Flow != h.flow && r.Flow != "any" {
				continue
			}
			// A global source still permits a restricted destination zone.
			// An empty destination zone must match no interfaces, not all traffic.
			if h.flow == "forward" && r.DstZone != "" {
				for _, out := range zones.members[r.DstZone] {
					if r.OutInterface != "" && r.OutInterface != out {
						continue
					}
					copy := r
					copy.OutInterface = ""
					b.emitRule(h.builtin, copy, " -o "+out)
				}
				continue
			}
			b.emitRule(h.builtin, r, "")
		}
	}

	// 2. Разбор по зонам: переход в цепочку по интерфейсу.
	b.iptvAccess(cfg)
	b.line("# --- разбор по зонам ---")
	// strongSwan 6.0.1 не всегда присваивает входящий XFRM ID трафику
	// road-warrior. Ядро уже проверило IPsec-политику, поэтому классифицируем
	// такой трафик до перехода по физическому WAN-интерфейсу.
	b.clientExitsAsWAN(cfg, targets)
	jumped := map[string]bool{}
	if ikev2ServerEnabled(cfg) && targets["VPN-IN"] {
		// An IKEv2 channel's packets match the IPsec policy too; its XFRM
		// interface puts them in the Internet zone first.
		for _, ch := range cfg.Channels {
			if iface := config.ChannelInterface(ch); ch.Enabled && ch.Type == "ikev2" {
				b.line("-A INPUT -i %s -j %s", iface, zoneTarget(targets, "WAN-IN"))
				b.line("-A FORWARD -i %s -j %s", iface, zoneTarget(targets, "WAN-FWD"))
				jumped["INPUT "+iface], jumped["FORWARD "+iface] = true, true
			}
		}
		b.line("-A INPUT -m policy --dir in --pol ipsec -j %s", ChainName("vpn", "IN"))
		b.line("-A FORWARD -m policy --dir in --pol ipsec -j %s", ChainName("vpn", "FWD"))
	}
	for _, c := range chains {
		for _, iface := range zones.members[c.zone.Name] {
			if !jumped[c.hook.builtin+" "+iface] {
				b.line("-A %s %s %s -j %s", c.hook.builtin, c.hook.selector, iface, c.chain)
			}
		}
	}

	// 3. Содержимое цепочек.
	for _, c := range chains {
		b.line("# --- %s: %s ---", c.chain, describeChain(c.zone, c.hook))

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
				for _, out := range zones.members[r.DstZone] {
					if r.OutInterface != "" && r.OutInterface != out {
						continue
					}
					copy := r
					copy.OutInterface = ""
					b.emitRule(c.chain, copy, " -o "+out)
				}
				continue
			}
			b.emitRule(c.chain, r, "")
		}

		// Проброшенные порты: без разрешения в форварде трансляция сработает,
		// а пакет всё равно не дойдёт.
		if c.hook.flow == "forward" && c.zone.Name == "wan" {
			b.portForwardAccept(cfg, c.chain)
			b.channelTransit(cfg, c.chain, zones.uplinks)
		}
		if c.hook.flow == "in" && c.zone.Name == "wan" {
			b.vpnServerAccept(cfg, c.chain)
		}
		if c.hook.flow == "forward" {
			b.intersegmentDefault(cfg, c.chain, c.zone.Name)
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
