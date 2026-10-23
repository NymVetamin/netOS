package qos

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

type clientClass struct {
	Class, Handle, Parent     string
	Root                      bool
	Prio                      int
	Rate, Ceil, Burst, Cburst uint64
}

type clientFilter struct {
	Protocol, Kind string
	Pref, Chain    int
	Options        *struct {
		Handle  uint64
		Classid string
		Keys    map[string]string
		NotInHW bool `json:"not_in_hw"`
		Actions []struct {
			Order, Index, Overhead, Ref, Bind int
			Kind                              string
			ControlAction                     struct{ Type string } `json:"control_action"`
		}
	}
}

func (s *Subsystem) readClientJSON(ctx context.Context, target any, args ...string) bool {
	out, err := s.Runner.Run(ctx, "tc", append([]string{"-j"}, args...)...)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(out))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil
}

// A matching topology lets us change rates without discarding the queues of
// other clients. Unknown state takes the ordinary reconstruction path.
func (s *Subsystem) clientRateUpdates(ctx context.Context, item clientInterface) ([][]string, bool) {
	if len(item.Download) == 0 && len(item.Upload) == 0 {
		return nil, false
	}
	var qdiscs []struct {
		Kind, Handle, Parent string
		Root                 bool
		Refcnt               int
		Options              map[string]json.RawMessage
	}
	if !s.readClientJSON(ctx, &qdiscs, "qdisc", "show", "dev", item.Name) {
		return nil, false
	}
	root, ingress := false, false
	for _, q := range qdiscs {
		switch {
		case len(item.Download) == 0 && q.Kind == "noqueue" && q.Handle == "0:" && q.Root && q.Parent == "" && len(q.Options) == 0 && !root:
			root = true
		case len(item.Download) > 0 && q.Kind == "htb" && q.Handle == "1:" && q.Root && !root:
			var def string
			if json.Unmarshal(q.Options["default"], &def) != nil || (def != "0x1" && def != "1") {
				return nil, false
			}
			var r2q, directQueue int
			if json.Unmarshal(q.Options["r2q"], &r2q) != nil || r2q != 10 || json.Unmarshal(q.Options["direct_qlen"], &directQueue) != nil || directQueue != 1000 {
				return nil, false
			}
			for key := range q.Options {
				switch key {
				case "default", "r2q", "direct_qlen", "direct_packets_stat":
				default:
					return nil, false
				}
			}
			root = true
		case q.Kind == "ingress" && q.Handle == "ffff:" && !ingress:
			ingress = true
		default:
			return nil, false
		}
	}
	if !root || ingress != (len(item.Upload) > 0) {
		return nil, false
	}
	var classes []clientClass
	wantClasses := 0
	if len(item.Download) > 0 {
		wantClasses = len(item.Download) + 1
	}
	if !s.readClientJSON(ctx, &classes, "class", "show", "dev", item.Name) || len(classes) != wantClasses {
		return nil, false
	}
	byID := map[string]clientClass{}
	for _, c := range classes {
		if c.Class != "htb" || c.Prio != 0 {
			return nil, false
		}
		if _, exists := byID[c.Handle]; exists {
			return nil, false
		}
		byID[c.Handle] = c
	}
	parent := byID["1:1"]
	if len(item.Download) > 0 && (!parent.Root || parent.Rate != 1250000000 || parent.Ceil != 1250000000) {
		return nil, false
	}
	var updates [][]string
	for i, client := range item.Download {
		id := fmt.Sprintf("1:%d", i+10)
		current, exists := byID[id]
		if !exists || current.Parent != "1:1" || current.Root {
			return nil, false
		}
		wanted := uint64(client.DownKbit) * 125
		if current.Rate != wanted || current.Ceil != wanted || current.Burst != 32768 {
			rate := fmt.Sprintf("%dkbit", client.DownKbit)
			updates = append(updates, []string{"class", "change", "dev", item.Name, "parent", "1:1", "classid", id, "htb", "rate", rate, "ceil", rate, "burst", "32k"})
		}
	}
	for _, direction := range []struct {
		parent, key string
		clients     []config.Client
	}{
		{"1:", "dst_mac", item.Download}, {"ffff:", "src_mac", item.Upload},
	} {
		if len(direction.clients) == 0 {
			continue
		}
		var filters []clientFilter
		if !s.readClientJSON(ctx, &filters, "filter", "show", "dev", item.Name, "parent", direction.parent) {
			return nil, false
		}
		seen := map[int]bool{}
		text := ""
		if direction.key == "src_mac" {
			var err error
			text, err = s.Runner.Run(ctx, "tc", "filter", "show", "dev", item.Name, "parent", direction.parent)
			if err != nil {
				return nil, false
			}
		}
		for _, filter := range filters {
			if filter.Kind != "flower" || filter.Protocol != "all" || filter.Chain != 0 {
				return nil, false
			}
			index := filter.Pref - 100
			if index < 0 || index >= len(direction.clients) {
				return nil, false
			}
			if filter.Options == nil {
				continue
			}
			if seen[index] {
				return nil, false
			}
			seen[index] = true
			options := filter.Options
			client := direction.clients[index]
			if options.Handle == 0 || len(options.Keys) != 1 || !strings.EqualFold(options.Keys[direction.key], client.MAC) {
				return nil, false
			}
			if direction.key == "dst_mac" {
				if options.Classid != fmt.Sprintf("1:%d", index+10) || len(options.Actions) != 0 {
					return nil, false
				}
				continue
			}
			if options.Classid != "" || len(options.Actions) != 1 || options.Actions[0].Kind != "police" || options.Actions[0].Order != 1 || options.Actions[0].ControlAction.Type != "drop" || options.Actions[0].Overhead != 0 {
				return nil, false
			}
			if !blockHasTokens(text, "filter ", fmt.Sprintf("pref=%d", filter.Pref), "src_mac="+strings.ToLower(client.MAC), fmt.Sprintf("rate=%dkbit", client.UpKbit), "burst=64kb", "mtu=64kb") {
				updates = append(updates, []string{"filter", "replace", "dev", item.Name, "parent", "ffff:", "protocol", "all", "pref", fmt.Sprint(filter.Pref), "handle", fmt.Sprintf("0x%x", options.Handle), "flower", "src_mac", client.MAC, "action", "police", "rate", fmt.Sprintf("%dkbit", client.UpKbit), "burst", "64k", "mtu", "64k", "conform-exceed", "drop"})
			}
		}
		if len(seen) != len(direction.clients) {
			return nil, false
		}
	}
	return updates, true
}

func (s *Subsystem) updateClientRates(ctx context.Context, item clientInterface) (bool, error) {
	updates, ok := s.clientRateUpdates(ctx, item)
	if !ok {
		return false, nil
	}
	for _, args := range updates {
		if _, err := s.Runner.Run(ctx, "tc", args...); err != nil {
			return true, err
		}
	}
	return true, nil
}
