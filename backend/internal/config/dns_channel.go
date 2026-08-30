package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type DNSChannelBinding struct {
	UpstreamID string
	ChannelID  string
	Address    netip.Addr
	Port       int
	Protocol   string
}

// DNSUpstreamEndpoints returns the actual IPv4 socket(s) opened by a resolver.
// A literal address is deliberately required for channel binding: resolving the
// resolver through itself would create a bootstrap loop and iptables cannot
// route a hostname.
func DNSUpstreamEndpoints(up Upstream) ([]DNSChannelBinding, error) {
	raw := strings.TrimSpace(up.Address)
	defaultPort := 53
	protocols := []string{"udp", "tcp"}
	switch up.Type {
	case "dot":
		defaultPort, protocols = 853, []string{"tcp"}
	case "doh":
		defaultPort, protocols = 443, []string{"tcp"}
	case "doq":
		defaultPort, protocols = 853, []string{"udp"}
	}

	host, port := "", defaultPort
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		host = parsed.Hostname()
		if parsed.Port() != "" {
			p, err := strconv.Atoi(parsed.Port())
			if err != nil {
				return nil, err
			}
			port = p
		}
	} else {
		raw, _, _ = strings.Cut(raw, "#")
		if before, after, ok := strings.Cut(raw, "@"); ok {
			host = before
			if after != "" {
				p, err := strconv.Atoi(after)
				if err != nil {
					return nil, err
				}
				port = p
			}
		} else if parsedHost, parsedPort, err := net.SplitHostPort(raw); err == nil {
			host = parsedHost
			p, err := strconv.Atoi(parsedPort)
			if err != nil {
				return nil, err
			}
			port = p
		} else {
			host = raw
		}
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("для привязки к каналу нужен буквальный IPv4-адрес DNS-сервера")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("порт DNS-сервера вне диапазона 1-65535")
	}
	bindings := make([]DNSChannelBinding, 0, len(protocols))
	for _, protocol := range protocols {
		bindings = append(bindings, DNSChannelBinding{UpstreamID: up.ID, Address: addr, Port: port, Protocol: protocol})
	}
	return bindings, nil
}

func (c *Config) DNSChannelBindings() []DNSChannelBinding {
	channels := map[string]string{}
	for _, up := range c.DNS.Upstreams {
		if up.Enabled && up.Channel != "" && up.Channel != "direct" {
			channels[up.ID] = up.Channel
		}
	}
	for _, rule := range c.DNS.SplitRules {
		if rule.Enabled && rule.Upstream != "" && rule.Channel != "" && rule.Channel != "direct" {
			channels[rule.Upstream] = rule.Channel
		}
	}
	var out []DNSChannelBinding
	for _, up := range c.DNS.Upstreams {
		channel := channels[up.ID]
		if !up.Enabled || channel == "" {
			continue
		}
		bindings, err := DNSUpstreamEndpoints(up)
		if err != nil {
			continue // validation reports the actionable error before Apply
		}
		for i := range bindings {
			bindings[i].ChannelID = channel
		}
		out = append(out, bindings...)
	}
	return out
}
