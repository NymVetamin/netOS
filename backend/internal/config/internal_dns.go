package config

// Порты внутренних DNS-служб на loopback.
const (
	// LocalDNSPort — подчинённый dnsmasq локальной зоны, когда порт DNS держит
	// другой резолвер. 5353 не берём: его занимает mDNS.
	LocalDNSPort = 5354
	// PolicyDNSBackendPort — выбранный резолвер за фронтендом dnsmasq.
	// 5356, а не 5355: 5355 до захвата resolv.conf держит LLMNR systemd-resolved.
	PolicyDNSBackendPort = 5356
)

// DNSFrontendNeeded also covers ocserv's transient worker interfaces. Neither
// unbound nor dnsproxy can bind an address that appears only after a VPN login;
// dnsmasq's bind-dynamic frontend follows those interfaces as clients connect.
func (c *Config) DNSFrontendNeeded() bool {
	if c == nil || !c.DNS.Enabled {
		return false
	}
	if c.KernelDomainPolicies() {
		return true
	}
	// dnsproxy verbose output does not provide a compact per-client query event.
	// Reuse the existing dnsmasq frontend, retaining encrypted upstream handling.
	if c.TrafficMonitor.Enabled && c.DNS.Provider == "dnsproxy" {
		return true
	}
	for _, server := range c.VPNServers {
		if server.Enabled && (server.Type == "ocserv" || server.Type == "l2tp") {
			return true
		}
	}
	return false
}

// KernelDomainPolicies сообщает, есть ли доменные политики, которые заполняют
// ipset через DNS (политики серверов Xray маршрутизирует сам Xray).
func (c *Config) KernelDomainPolicies() bool {
	if c == nil || !c.DNS.Enabled {
		return false
	}
	xrayServers := map[string]bool{}
	for _, server := range c.VPNServers {
		if server.Type == "xray" {
			xrayServers[server.ID] = true
		}
	}
	for _, item := range c.Policies {
		if item.Enabled && len(item.Domains) > 0 && !xrayServers[item.VPNServer] {
			return true
		}
	}
	return false
}

// LocalDNSNeeded сообщает, работает ли dnsmasq подчинённым резолвером
// локальной зоны — то есть DHCP раздаёт он, а порт DNS держит кто-то другой.
func (c *Config) LocalDNSNeeded() bool {
	return c != nil && c.DHCP.Enabled && c.DHCP.Provider == "dnsmasq" &&
		c.DNS.Enabled && c.DNS.Provider != "dnsmasq"
}

// internalDNSPortBusy сообщает, занимает ли порт внутренняя DNS-служба именно
// в этой конфигурации. Запрещать порт всегда нельзя: панель или SOCKS на нём
// законно работали без этих служб, а ошибка валидации останавливает netosd
// при старте — после обновления администратор остался бы без панели.
func (c *Config) internalDNSPortBusy(port int) bool {
	switch port {
	case LocalDNSPort:
		// При фронтенде локальную зону обслуживает он сам, на порту DNS.
		return c.LocalDNSNeeded() && !c.DNSFrontendNeeded()
	case PolicyDNSBackendPort:
		return c.DNS.Provider != "dnsmasq" && c.DNSFrontendNeeded()
	}
	return false
}
