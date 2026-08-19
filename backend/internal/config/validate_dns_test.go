package config

import (
	"strings"
	"testing"
)

// Локальные имена клиентов резолверу отдаёт только dnsmasq: он раздал адреса и
// потому единственный знает, какое имя за кем закреплено. С ISC DHCP или Kea
// такого моста нет, и молчать об этом нельзя — администратор видит в
// настройках локальный домен и считает, что имена работают.
func TestWarnsThatClientNamesNeedDnsmasq(t *testing.T) {
	const want = "имена клиентов"

	cases := []struct {
		name     string
		dhcp     string
		dns      string
		expected bool
	}{
		{"ISC и unbound", "isc-dhcp-server", "unbound", true},
		{"Kea и dnsproxy", "kea", "dnsproxy", true},
		{"dnsmasq раздаёт адреса", "dnsmasq", "unbound", false},
		{"dnsmasq держит и порт 53", "dnsmasq", "dnsmasq", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.DHCP.Enabled, c.DHCP.Provider = true, tc.dhcp
			c.DNS.Enabled, c.DNS.Provider = true, tc.dns

			var found bool
			for _, p := range c.Validate().Problems {
				if strings.Contains(p.Message, want) {
					found = true
					if p.Severity != "warning" {
						t.Errorf("рабочую связку запрещаем, а не предупреждаем: %s", p.Severity)
					}
				}
			}
			if found != tc.expected {
				t.Errorf("предупреждение о локальных именах: получено %v, ожидалось %v", found, tc.expected)
			}
		})
	}
}
