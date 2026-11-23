package netiface

import "github.com/netos-router/netos/internal/config"

// interfaceApplyLookup belongs to one Apply, including all of its configure
// calls. First matches preserve Config's ID/name lookup semantics.
type interfaceApplyLookup struct {
	enabled      map[string]bool
	byID         map[string]string
	enabledNames map[string]bool
}

func newInterfaceApplyLookup(cfg *config.Config) interfaceApplyLookup {
	out := interfaceApplyLookup{enabled: cfg.InterfaceStates()}
	for _, iface := range cfg.Interfaces {
		if len(iface.Members) > 0 {
			out.byID = make(map[string]string, len(cfg.Interfaces))
			out.enabledNames = make(map[string]bool, len(cfg.Interfaces))
			break
		}
	}
	if out.byID == nil {
		return out
	}
	for _, iface := range cfg.Interfaces {
		if _, found := out.byID[iface.ID]; !found {
			out.byID[iface.ID] = iface.Name
		}
		if _, found := out.enabledNames[iface.Name]; !found {
			out.enabledNames[iface.Name] = out.enabled[iface.ID]
		}
	}
	return out
}

func (l interfaceApplyLookup) names(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := l.byID[id]; name != "" {
			out = append(out, name)
		}
	}
	return out
}
