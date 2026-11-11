package api

import (
	"encoding/json"
	"strconv"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/configdiff"
)

func formatPlanValue(value configdiff.Value, field planField, cfg *config.Config) string {
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
			if cfg != nil {
				for _, ch := range cfg.Channels {
					if field.Reference == "channel" && ch.ID == v && ch.Name != "" {
						return ch.Name + " (" + v + ")"
					}
				}
				for _, wan := range cfg.WANs {
					if wan.ID == v && wan.Name != "" {
						return wan.Name + " (" + v + ")"
					}
				}
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
	case float64:
		if field.Format == "mbit" {
			if v == 0 {
				return "Без ограничения"
			}
			v /= 1000
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		// Never serialize a whole object: its children may have secret fields.
		for _, item := range v {
			switch item.(type) {
			case string, float64, bool, nil:
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
	"proto":         {"static": "Статический адрес", "dhcp": "DHCP", "pppoe": "PPPoE"},
	"type":          {"wireguard": "WireGuard", "xray": "Xray", "ikev2": "IKEv2", "openconnect": "OpenConnect", "ocserv": "OpenConnect", "l2tp": "L2TP", "bridge": "Мост", "vlan": "VLAN", "dot": "DoT", "doh": "DoH", "doq": "DoQ", "plain": "Обычный DNS"},
	"fail_mode":     {"drop": "Блокировать трафик", "direct": "Напрямую", "fallback": "Запасной канал"},
	"output_policy": {"ACCEPT": "Разрешать", "DROP": "Запрещать"},
	"action":        {"accept": "Разрешить", "drop": "Отбросить", "reject": "Отклонить"},
}
