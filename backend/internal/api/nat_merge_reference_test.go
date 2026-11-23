package api

import (
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"reflect"
)

func oldMergeNetworkNAT(previous, visible, incoming *config.Config) (config.Firewall, error) {
	deny := func() (config.Firewall, error) {
		return config.Firewall{}, fmt.Errorf("в разделе Сеть доступен только тумблер NAT аплинка")
	}
	check := incoming.Firewall
	check.NAT = visible.Firewall.NAT
	if !reflect.DeepEqual(check, visible.Firewall) {
		return deny()
	}
	result := previous.Firewall
	result.NAT = append([]config.NATRule(nil), previous.Firewall.NAT...)
	old := map[string]config.NATRule{}
	manual := map[string]bool{}
	for _, rule := range visible.Firewall.NAT {
		old[rule.ID] = rule
		if !rule.System {
			manual[rule.Interface] = true
		}
	}
	seen := map[string]bool{}
	isWANMasquerade := wanMasqueradeMatcher(previous)
	for _, rule := range incoming.Firewall.NAT {
		if seen[rule.ID] {
			return deny()
		}
		seen[rule.ID] = true
		if existing, ok := old[rule.ID]; ok {
			check := rule
			check.Enabled = existing.Enabled
			if !reflect.DeepEqual(check, existing) {
				return deny()
			}
			if rule.Enabled != existing.Enabled && (!existing.System || !isWANMasquerade(existing) || manual[existing.Interface]) {
				return deny()
			}
			for i := range result.NAT {
				if result.NAT[i].ID == rule.ID {
					result.NAT[i].Enabled = rule.Enabled
				}
			}
			continue
		}
		valid := false
		for _, wan := range incoming.WANs {
			iface := wanDevice(incoming, wan)
			if iface == "" || manual[iface] {
				continue
			}
			expected := config.NATRule{ID: "wan-nat-" + wan.ID, Name: fmt.Sprintf("NAT аплинка «%s»", wan.Name), System: true, Enabled: rule.Enabled, Direction: "source", Interface: iface}
			if reflect.DeepEqual(rule, expected) {
				valid = true
				break
			}
		}
		if !valid {
			return deny()
		}
		for _, existing := range result.NAT {
			if existing.ID == rule.ID {
				return deny()
			}
			if existing.Interface == rule.Interface && existing.Direction != "destination" && existing.Source == "" && existing.ToSource == "" {
				return deny()
			}
		}
		result.NAT = append(result.NAT, rule)
	}
	for id := range old {
		if !seen[id] {
			return deny()
		}
	}
	return result, nil
}
