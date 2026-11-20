package api

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/configdiff"
)

// A plan compares two snapshots, each with its own names. Build each index
// on the first reference that needs it.
type planNames struct {
	cfg      *config.Config
	channels map[string]string
	wans     map[string]string
}

func (n *planNames) lookup(reference, id string) string {
	if n == nil || n.cfg == nil {
		return ""
	}
	if reference == "channel" {
		if n.channels == nil {
			n.channels = make(map[string]string, len(n.cfg.Channels))
			for _, ch := range n.cfg.Channels {
				if ch.Name != "" && n.channels[ch.ID] == "" {
					n.channels[ch.ID] = ch.Name
				}
			}
		}
		if name := n.channels[id]; name != "" {
			return name
		}
	}
	if n.wans == nil {
		n.wans = make(map[string]string, len(n.cfg.WANs))
		for _, wan := range n.cfg.WANs {
			if wan.Name != "" && n.wans[wan.ID] == "" {
				n.wans[wan.ID] = wan.Name
			}
		}
	}
	return n.wans[id]
}

func formatPlanValue(value configdiff.Value, field planField, names *planNames) string {
	if !value.Present {
		return "Отсутствует"
	}
	if value.Data == nil {
		return "Не задано"
	}
	if field.Sensitive {
		return "Скрыто"
	}
	switch v := value.Data.(type) {
	case string:
		if v == "" {
			return "Не задано"
		}
		if translated := planEnumLabels[field.Key][v]; translated != "" {
			return translated
		}
		if field.Reference == "channel" || field.Reference == "wan" {
			if field.Reference == "channel" && v == config.InternetBlockChannel {
				return "Блок — без интернета"
			}
			if v == "direct" {
				return "Напрямую"
			}
			if name := names.lookup(field.Reference, v); name != "" {
				return name + " (" + v + ")"
			}
		}
		return v
	case bool:
		if field.Format == "switch" {
			if v {
				return "Включено"
			}
			return "Выключено"
		}
		if v {
			return "Да"
		}
		return "Нет"
	case json.Number:
		if field.Format == "mbit" {
			if v == "0" {
				return "Без ограничения"
			}
			// Bandwidth is stored in whole kbit/s. Move the decimal point
			// without rounding the original integer through float64.
			digits := strings.TrimPrefix(v.String(), "-")
			if len(digits) < 4 {
				digits = strings.Repeat("0", 4-len(digits)) + digits
			}
			point := len(digits) - 3
			result := strings.TrimRight(strings.TrimRight(digits[:point]+"."+digits[point:], "0"), ".")
			if v[0] == '-' {
				return "-" + result
			}
			return result
		}
		if strings.ContainsAny(v.String(), "eE") {
			if f, err := v.Float64(); err == nil {
				return strconv.FormatFloat(f, 'f', -1, 64)
			}
		}
		return v.String()
	case []any:
		// Never serialize a whole object: its children may have secret fields.
		for _, item := range v {
			switch item.(type) {
			case string, json.Number, bool, nil:
			default:
				return "Список: " + strconv.Itoa(len(v)) + " элементов"
			}
		}
		raw, _ := json.Marshal(v)
		return string(raw)
	case map[string]any:
		return "Объект: " + strconv.Itoa(len(v)) + " полей"
	}
	return "Значение изменено"
}

var planEnumLabels = map[string]map[string]string{
	"underlay":      {"dhcp": "Получать по DHCP", "static": "Задать вручную"},
	"proto":         {"static": "Статический адрес", "dhcp": "DHCP", "pppoe": "PPPoE"},
	"type":          {"wireguard": "WireGuard", "xray": "Xray", "ikev2": "IKEv2", "openconnect": "OpenConnect", "ocserv": "OpenConnect", "l2tp": "L2TP", "bridge": "Мост", "vlan": "VLAN", "dot": "DoT", "doh": "DoH", "doq": "DoQ", "plain": "Обычный DNS"},
	"fail_mode":     {"drop": "Блокировать трафик", "direct": "Напрямую", "fallback": "Запасной канал"},
	"output_policy": {"ACCEPT": "Разрешать", "DROP": "Запрещать"},
	"action":        {"accept": "Разрешить", "drop": "Отбросить", "reject": "Отклонить"},
}
