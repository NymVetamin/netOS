package api

import (
	"fmt"
	"reflect"

	"github.com/netos-router/netos/internal/config"
)

func wanDevice(cfg *config.Config, wan config.WAN) string {
	if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
		return "ppp-" + wan.ID
	}
	for _, port := range cfg.Interfaces {
		if port.ID == wan.Interface {
			return port.Name
		}
	}
	return ""
}

// Each projection/merge owns its matcher; a later configuration gets a fresh one.
func wanMasqueradeMatcher(cfg *config.Config) func(config.NATRule) bool {
	var devices map[string]bool
	return func(rule config.NATRule) bool {
		if len(cfg.WANs) == 0 || rule.Direction == "destination" || rule.Source != "" || rule.ToSource != "" || rule.Interface == "" {
			return false
		}
		if devices == nil {
			names := make(map[string]string, len(cfg.Interfaces))
			for _, port := range cfg.Interfaces {
				if _, exists := names[port.ID]; !exists {
					names[port.ID] = port.Name
				}
			}
			devices = make(map[string]bool, len(cfg.WANs))
			for _, wan := range cfg.WANs {
				name := names[wan.Interface]
				if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
					name = "ppp-" + wan.ID
				}
				devices[name] = true
			}
		}
		return devices[rule.Interface]
	}
}

// The Network page owns the uplink NAT switch, not arbitrary firewall rules.
func mergeNetworkNAT(previous, visible, incoming *config.Config) (config.Firewall, error) {
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
	positions := make(map[string][]int, len(result.NAT))
	masquerades := make(map[string]bool)
	for i, rule := range result.NAT {
		positions[rule.ID] = append(positions[rule.ID], i)
		if rule.Direction != "destination" && rule.Source == "" && rule.ToSource == "" {
			masquerades[rule.Interface] = true
		}
	}
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
	var expectedNew map[config.NATRule]bool
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
			for _, i := range positions[rule.ID] {
				result.NAT[i].Enabled = rule.Enabled
			}
			continue
		}
		if expectedNew == nil {
			if len(incoming.WANs) == 0 {
				return deny()
			}
			expectedNew = make(map[config.NATRule]bool, len(incoming.WANs))
			names := make(map[string]string, len(incoming.Interfaces))
			for _, port := range incoming.Interfaces {
				if _, exists := names[port.ID]; !exists {
					names[port.ID] = port.Name
				}
			}
			for _, wan := range incoming.WANs {
				iface := names[wan.Interface]
				if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
					iface = "ppp-" + wan.ID
				}
				if iface == "" || manual[iface] {
					continue
				}
				expectedNew[config.NATRule{ID: "wan-nat-" + wan.ID, Name: fmt.Sprintf("NAT аплинка «%s»", wan.Name), System: true, Direction: "source", Interface: iface}] = true
			}
		}
		candidate := rule
		candidate.Enabled = false
		if !expectedNew[candidate] {
			return deny()
		}
		if len(positions[rule.ID]) != 0 || masquerades[rule.Interface] {
			return deny()
		}
		positions[rule.ID] = []int{len(result.NAT)}
		masquerades[rule.Interface] = true
		result.NAT = append(result.NAT, rule)
	}
	for id := range old {
		if !seen[id] {
			return deny()
		}
	}
	return result, nil
}
