package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/netos-router/netos/internal/config"
)

// Roots edited by each page. Shared selectors are handled explicitly below.
var rootSections = map[string][]string{
	"traffic_monitor": {"system", "dashboard"},
	"system":          {"system"}, "ipv6": {"system"}, "interfaces": {"network"}, "networks": {"network"},
	"wans": {"network"}, "multiwan": {"network"}, "routing": {"routing"}, "firewall": {"firewall"},
	"dhcp": {"services"}, "dns": {"services"}, "socks": {"services"}, "iptv": {"services"}, "clients": {"clients"},
	"channels": {"channels"}, "policies": {"channels"}, "vpn_servers": {"vpn-servers"},
	"wifi": {"wifi"}, "qos": {"traffic"}, "ddns": {"services"}, "samba": {"storage"}, "components": {"components"},
}

func configObject(cfg *config.Config) map[string]any {
	b, _ := json.Marshal(cfg)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func objectConfig(m map[string]any) (*config.Config, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var c config.Config
	err = json.Unmarshal(b, &c)
	return &c, err
}

func selectFields(v any, fields ...string) map[string]any {
	m, _ := v.(map[string]any)
	out := map[string]any{}
	for _, k := range fields {
		if x, ok := m[k]; ok {
			out[k] = x
		}
	}
	return out
}

func selectList(v any, fields ...string) []any {
	list, _ := v.([]any)
	out := []any{}
	for _, item := range list {
		out = append(out, selectFields(item, fields...))
	}
	return out
}

func scopedConfig(r *http.Request, cfg *config.Config) (*config.Config, error) {
	redacted, err := redactAdminConfig(cfg)
	if err != nil {
		return nil, err
	}
	return projectConfig(r, redacted)
}

// projectConfig only selects fields permitted to this account. Redaction and
// comparison are separate consumers; API configuration reads use scopedConfig.
func projectConfig(r *http.Request, cfg *config.Config) (*config.Config, error) {
	if roleOf(r) == "admin" {
		return cfg, nil
	}
	full := configObject(cfg)
	visible := configObject(&config.Config{Version: cfg.Version})
	for key, sections := range rootSections {
		if anySection(r, false, sections...) {
			visible[key] = full[key]
		}
	}
	if may(r, "diagnostics", false) && !may(r, "services", false) {
		visible["dns"] = selectFields(full["dns"], "query_log")
	}
	// Cross-section selectors get only labels and topology, not service settings.
	if anySection(r, false, "dashboard", "map", "clients", "network", "routing", "channels", "vpn-servers", "wifi", "traffic", "firewall", "services", "storage") {
		if !may(r, "network", false) {
			visible["wans"] = selectList(full["wans"], "id", "name", "interface", "enabled", "proto", "index")
		}
		if !may(r, "services", false) {
			visible["dhcp"] = selectFields(full["dhcp"], "enabled", "provider")
		}
		if !may(r, "network", false) {
			visible["interfaces"] = selectList(full["interfaces"], "id", "name", "label", "type", "enabled", "members", "parent", "vlan_id")
			visible["networks"] = selectList(full["networks"], "id", "name", "interface", "router_address", "enabled", "default_channel")
		}
		if !may(r, "channels", false) {
			visible["channels"] = selectList(full["channels"], "id", "name", "type", "enabled", "index")
		}
		if !may(r, "vpn-servers", false) {
			servers := selectList(full["vpn_servers"], "id", "name", "type", "enabled", "index", "subnet", "default_channel")
			if anySection(r, false, "map", "clients", "dashboard") {
				original, _ := full["vpn_servers"].([]any)
				for i, item := range original {
					servers[i].(map[string]any)["peers"] = selectList(item.(map[string]any)["peers"], "id", "name", "enabled", "address", "channel")
				}
			}
			visible["vpn_servers"] = servers
		}
		if !may(r, "components", false) {
			visible["components"] = full["components"]
		}
	}
	if may(r, "network", false) && !may(r, "firewall", false) {
		out, err := objectConfig(visible)
		if err != nil {
			return nil, err
		}
		for _, rule := range cfg.Firewall.NAT {
			if isWANMasquerade(cfg, rule) {
				out.Firewall.NAT = append(out.Firewall.NAT, rule)
			}
		}
		visible = configObject(out)
	}
	if may(r, "services", false) && !may(r, "system", false) {
		visible["ipv6"] = selectFields(full["ipv6"], "filter_aaaa")
	}
	if anySection(r, false, "clients", "map", "dashboard") && !may(r, "services", false) {
		visible["dhcp"] = selectFields(full["dhcp"], "enabled", "provider", "reservations")
	}
	if anySection(r, false, "map", "dashboard") {
		visible["system"].(map[string]any)["hostname"] = cfg.System.Hostname
	}
	return objectConfig(visible)
}

// Merge only authorized differences into the private full draft. Hidden fields
// are never supplied by the browser and cannot be overwritten with zero values.
func mergeScopedConfig(r *http.Request, previous, incoming *config.Config) (*config.Config, error) {
	if roleOf(r) == "admin" {
		out, err := objectConfig(configObject(incoming))
		if err != nil {
			return nil, err
		}
		mergeRedactedSecrets(out, previous)
		out.Normalize()
		return out, nil
	}
	shown, err := scopedConfig(r, previous)
	if err != nil {
		return nil, err
	}
	before, next, merged := configObject(shown), configObject(incoming), configObject(previous)
	for key, value := range next {
		if reflect.DeepEqual(value, before[key]) {
			continue
		}
		if anySection(r, true, rootSections[key]...) {
			merged[key] = value
			continue
		}
		if key == "firewall" && may(r, "network", true) {
			firewall, err := mergeNetworkNAT(previous, shown, incoming)
			if err != nil {
				return nil, err
			}
			copy := *previous
			copy.Firewall = firewall
			merged[key] = configObject(&copy)[key]
			continue
		}
		if key == "dhcp" && may(r, "clients", true) {
			neu := selectFields(value, "reservations")
			// Compare every field except the authorized reservation list.
			b, _ := json.Marshal(before[key])
			var bmap map[string]any
			_ = json.Unmarshal(b, &bmap)
			delete(bmap, "reservations")
			b, _ = json.Marshal(value)
			var nmap map[string]any
			_ = json.Unmarshal(b, &nmap)
			delete(nmap, "reservations")
			if !reflect.DeepEqual(bmap, nmap) {
				return nil, fmt.Errorf("нет права менять DHCP")
			}
			merged[key].(map[string]any)["reservations"] = neu["reservations"]
			continue
		}
		if key == "vpn_servers" && may(r, "clients", true) {
			b, _ := before[key].([]any)
			n, _ := value.([]any)
			m, _ := merged[key].([]any)
			if len(b) != len(n) {
				return nil, fmt.Errorf("нет права менять VPN-серверы")
			}
			for i := range b {
				bs := b[i].(map[string]any)
				ns := n[i].(map[string]any)
				bp, _ := bs["peers"].([]any)
				np, _ := ns["peers"].([]any)
				if len(bp) != len(np) {
					return nil, fmt.Errorf("нет права менять состав VPN-клиентов")
				}
				for j := range bp {
					old := bp[j].(map[string]any)
					neu := np[j].(map[string]any)
					channel := neu["channel"]
					if original, exists := old["channel"]; exists {
						neu["channel"] = original
					} else {
						delete(neu, "channel")
					}
					if !reflect.DeepEqual(old, neu) {
						return nil, fmt.Errorf("доступен только канал VPN-клиента")
					}
					m[i].(map[string]any)["peers"].([]any)[j].(map[string]any)["channel"] = channel
				}
				if !reflect.DeepEqual(bs, ns) {
					return nil, fmt.Errorf("нет права менять VPN-сервер")
				}
			}
			continue
		}
		return nil, fmt.Errorf("нет права менять раздел %s", key)
	}
	out, err := objectConfig(merged)
	if err != nil {
		return nil, err
	}
	mergeRedactedSecrets(out, previous)
	out.Normalize()
	return out, nil
}
