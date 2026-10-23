package policy

import (
	"context"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func (s *Subsystem) unusedStaticSetsOnly(ctx context.Context, old, next *config.Config) bool {
	if old == nil || !domainPoliciesEqual(old, next) {
		return false
	}
	before, after := map[string]ownedSet{}, map[string]ownedSet{}
	for _, item := range desiredSets(old) {
		before[item.Name] = item
	}
	for _, item := range desiredSets(next) {
		after[item.Name] = item
	}
	changed := map[string]string{}
	for name, item := range before {
		if !reflect.DeepEqual(item, after[name]) {
			if !item.Static {
				return false
			}
			changed[name] = item.Policy
		}
	}
	for name, item := range after {
		if !reflect.DeepEqual(item, before[name]) {
			if !item.Static {
				return false
			}
			changed[name] = item.Policy
		}
	}
	if len(changed) == 0 {
		return false
	}
	for _, cfg := range []*config.Config{old, next} {
		for _, rule := range cfg.Firewall.Rules {
			if !rule.Enabled {
				continue
			}
			for _, id := range changed {
				if rule.SrcIPSet == id || rule.DstIPSet == id {
					return false
				}
			}
		}
	}
	if s.Health(ctx, old) != nil {
		return false
	}
	names, err := s.Runner.Run(ctx, "ipset", "list", "-name")
	if err != nil {
		return false
	}
	live := parseSetNames(names)
	for name := range changed {
		if !live[name] {
			if _, existed := before[name]; existed {
				return false
			}
			continue
		}
		if _, owned := before[name]; !owned {
			return false
		}
		detail, err := s.Runner.Run(ctx, "ipset", "list", name)
		if err != nil {
			return false
		}
		// Kernel references include rules outside the saved netOS configuration.
		zero := false
		for _, line := range strings.Split(detail, "\n") {
			if strings.HasPrefix(line, "References:") {
				if zero || strings.TrimSpace(strings.TrimPrefix(line, "References:")) != "0" {
					return false
				}
				zero = true
			}
		}
		if !zero {
			return false
		}
	}
	return true
}
