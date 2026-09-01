// Package qos manages the traffic-control objects owned by netOS.
package qos

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type ownedLink struct {
	WAN       string `json:"wan"`
	Interface string `json:"interface"`
	IFB       string `json:"ifb"`
}

type Subsystem struct {
	Runner    system.Runner
	StateDir  string
	writeFile func(string, []byte, os.FileMode) error
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir, writeFile: system.WriteFileAtomic}
}

func (s *Subsystem) Name() string { return "qos" }

func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	var before config.QoS
	if old != nil {
		before = old.QoS
	}
	var oldClients []config.Client
	if old != nil {
		oldClients = old.Clients
	}
	qosChanged := !equalQoS(before, next.QoS)
	clientsChanged := !equalClientLimits(oldClients, next.Clients)
	if !qosChanged && !clientsChanged {
		if err := s.Health(context.Background(), next); err != nil {
			return []apply.Action{{Subsystem: s.Name(), Kind: "update", Target: "очереди трафика", Detail: "исправление расхождения с живым QoS", Disruptive: true}}, nil
		}
		return nil, nil
	}
	var actions []apply.Action
	if qosChanged {
		kind := "update"
		if next.QoS.Enabled && !before.Enabled {
			kind = "create"
		} else if !next.QoS.Enabled && before.Enabled {
			kind = "delete"
		}
		actions = append(actions, apply.Action{Subsystem: s.Name(), Kind: kind, Target: "очереди трафика", Detail: "CAKE на интернет-каналах", Disruptive: true})
	}
	if clientsChanged {
		beforeLimits, afterLimits := hasClientLimits(oldClients), hasClientLimits(next.Clients)
		kind := "update"
		if afterLimits && !beforeLimits {
			kind = "create"
		} else if !afterLimits && beforeLimits {
			kind = "delete"
		}
		actions = append(actions, apply.Action{Subsystem: s.Name(), Kind: kind, Target: "лимиты клиентов", Detail: "HTB и policing по MAC-адресам", Disruptive: true})
	}
	return actions, nil
}

func hasClientLimits(clients []config.Client) bool {
	for _, client := range clients {
		if client.DownKbit > 0 || client.UpKbit > 0 {
			return true
		}
	}
	return false
}

func equalQoS(left, right config.QoS) bool {
	if left.Enabled != right.Enabled || len(left.WANs) != len(right.WANs) {
		return false
	}
	canonical := func(items []config.QoSWAN) []config.QoSWAN {
		result := append([]config.QoSWAN(nil), items...)
		for i := range result {
			if result[i].Diffserv == "" {
				result[i].Diffserv = "diffserv4"
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].WAN < result[j].WAN })
		return result
	}
	a, b := canonical(left.WANs), canonical(right.WANs)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalClientLimits(left, right []config.Client) bool {
	type limit struct {
		MAC, Network string
		Down, Up     int
	}
	canonical := func(clients []config.Client) []limit {
		result := make([]limit, 0, len(clients))
		for _, client := range clients {
			if client.DownKbit == 0 && client.UpKbit == 0 {
				continue
			}
			result = append(result, limit{strings.ToLower(client.MAC), client.Network, client.DownKbit, client.UpKbit})
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].Network != result[j].Network {
				return result[i].Network < result[j].Network
			}
			return result[i].MAC < result[j].MAC
		})
		return result
	}
	return reflect.DeepEqual(canonical(left), canonical(right))
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	previous, err := s.readOwned()
	if err != nil {
		return err
	}
	if err := s.Health(ctx, cfg); err == nil {
		return nil
	}
	if !cfg.QoS.Enabled {
		for _, item := range previous {
			if err := s.remove(ctx, item); err != nil {
				return fmt.Errorf("удаление QoS %s: %w", item.WAN, err)
			}
		}
		if err := s.writeOwned(nil); err != nil {
			return err
		}
		return s.applyClients(ctx, cfg)
	}

	ownedIFB := map[string]bool{}
	for _, item := range previous {
		ownedIFB[item.IFB] = true
	}
	wanted, err := desiredLinks(cfg)
	if err != nil {
		return err
	}
	// Check all targets before changing an existing queue. This keeps a typo or
	// an IFB collision from tearing down a working configuration.
	for _, item := range wanted {
		if _, err := s.Runner.Run(ctx, "ip", "link", "show", "dev", item.Interface); err != nil {
			return fmt.Errorf("интерфейс %s для %s недоступен: %w", item.Interface, item.WAN, err)
		}
		if _, err := s.Runner.Run(ctx, "ip", "link", "show", "dev", item.IFB); err == nil && !ownedIFB[item.IFB] {
			return fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", item.IFB)
		}
	}

	wantedKey := map[string]bool{}
	for _, item := range wanted {
		wantedKey[item.Interface+"\x00"+item.IFB] = true
	}
	for _, item := range previous {
		if !wantedKey[item.Interface+"\x00"+item.IFB] {
			if err := s.remove(ctx, item); err != nil {
				return fmt.Errorf("удаление QoS %s: %w", item.WAN, err)
			}
		}
	}

	settings := map[string]config.QoSWAN{}
	for _, item := range cfg.QoS.WANs {
		settings[item.WAN] = item
	}
	for _, item := range wanted {
		if err := s.applyLink(ctx, item, settings[item.WAN], ownedIFB[item.IFB]); err != nil {
			if !ownedIFB[item.IFB] {
				if cleanupErr := s.remove(ctx, item); cleanupErr != nil {
					recovery := append(append([]ownedLink(nil), previous...), item)
					stateErr := s.writeOwned(recovery)
					return fmt.Errorf("QoS %s: %w; уборка нового объекта: %v; сохранение ownership: %v", item.WAN, err, cleanupErr, stateErr)
				}
			}
			return fmt.Errorf("QoS %s: %w", item.WAN, err)
		}
	}
	if err := s.writeOwned(wanted); err != nil {
		var cleanupErrs []string
		for _, item := range wanted {
			if !ownedIFB[item.IFB] {
				if cleanupErr := s.remove(ctx, item); cleanupErr != nil {
					cleanupErrs = append(cleanupErrs, cleanupErr.Error())
				}
			}
		}
		if len(cleanupErrs) > 0 {
			return fmt.Errorf("%w; уборка после отказа записи ownership: %s", err, strings.Join(cleanupErrs, "; "))
		}
		return err
	}
	return s.applyClients(ctx, cfg)
}

func desiredLinks(cfg *config.Config) ([]ownedLink, error) {
	interfaces := map[string]string{}
	for _, item := range cfg.Interfaces {
		interfaces[item.ID] = item.Name
	}
	wans := map[string]config.WAN{}
	for _, item := range cfg.WANs {
		wans[item.ID] = item
	}
	result := make([]ownedLink, 0, len(cfg.QoS.WANs))
	for _, setting := range cfg.QoS.WANs {
		wan, ok := wans[setting.WAN]
		if !ok {
			return nil, fmt.Errorf("интернет-канал %s не найден", setting.WAN)
		}
		name := interfaces[wan.Interface]
		if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
			name = "ppp-" + wan.ID
		}
		if name == "" {
			return nil, fmt.Errorf("у интернет-канала %s нет системного интерфейса", wan.ID)
		}
		result = append(result, ownedLink{WAN: wan.ID, Interface: name, IFB: fmt.Sprintf("ifb-netos-%d", wan.Index)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].WAN < result[j].WAN })
	return result, nil
}

func (s *Subsystem) applyLink(ctx context.Context, item ownedLink, setting config.QoSWAN, ifbOwned bool) error {
	if !ifbOwned {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", item.IFB, "type", "ifb"); err != nil {
			return fmt.Errorf("создание %s: %w", item.IFB, err)
		}
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", item.IFB, "up"); err != nil {
		return err
	}
	profile := setting.Diffserv
	if profile == "" {
		profile = "diffserv4"
	}
	if _, err := s.Runner.Run(ctx, "tc", "qdisc", "replace", "dev", item.Interface, "root", "cake", "bandwidth", fmt.Sprintf("%dkbit", setting.UploadKbit), profile, "nat"); err != nil {
		return fmt.Errorf("исходящая очередь: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "tc", "qdisc", "replace", "dev", item.Interface, "handle", "ffff:", "ingress"); err != nil {
		return fmt.Errorf("входящая очередь: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "tc", "filter", "replace", "dev", item.Interface, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", item.IFB); err != nil {
		return fmt.Errorf("перенаправление входящего трафика: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "tc", "qdisc", "replace", "dev", item.IFB, "root", "cake", "bandwidth", fmt.Sprintf("%dkbit", setting.DownloadKbit), profile, "nat", "wash", "ingress"); err != nil {
		return fmt.Errorf("очередь загрузки: %w", err)
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	var links []ownedLink
	if cfg.QoS.Enabled {
		links, err = desiredLinks(cfg)
	}
	if err != nil {
		return err
	}
	if !sameOwnedLinks(owned, links) {
		return fmt.Errorf("список принадлежащих netOS QoS-интерфейсов не соответствует конфигурации")
	}
	settings := map[string]config.QoSWAN{}
	for _, item := range cfg.QoS.WANs {
		settings[item.WAN] = item
	}
	for _, item := range links {
		setting := settings[item.WAN]
		profile := setting.Diffserv
		if profile == "" {
			profile = "diffserv4"
		}
		out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", item.Interface)
		if err != nil || !lineHasTokens(out, "qdisc", "cake", "root", fmt.Sprintf("%dkbit", setting.UploadKbit), profile, "nat") || !lineHasTokens(out, "qdisc", "ingress") {
			return fmt.Errorf("исходящая очередь CAKE или ingress на %s не соответствует конфигурации", item.Interface)
		}
		filter, err := s.Runner.Run(ctx, "tc", "filter", "show", "dev", item.Interface, "parent", "ffff:")
		if err != nil || !outputHasTokens(filter, "mirred", "redirect", item.IFB) {
			return fmt.Errorf("перенаправление входящего трафика с %s на %s не работает", item.Interface, item.IFB)
		}
		out, err = s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", item.IFB)
		if err != nil || !lineHasTokens(out, "qdisc", "cake", "root", fmt.Sprintf("%dkbit", setting.DownloadKbit), profile, "nat", "wash", "ingress") {
			return fmt.Errorf("очередь загрузки CAKE на %s не соответствует конфигурации", item.IFB)
		}
	}
	return s.healthClients(ctx, cfg)
}

func (s *Subsystem) remove(ctx context.Context, item ownedLink) error {
	for _, command := range [][]string{
		{"tc", "qdisc", "del", "dev", item.Interface, "root"},
		{"tc", "qdisc", "del", "dev", item.Interface, "ingress"},
		{"ip", "link", "del", "dev", item.IFB},
	} {
		if _, err := s.Runner.Run(ctx, command[0], command[1:]...); err != nil && !missingTrafficObject(err) {
			return err
		}
	}
	if out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", item.Interface); err == nil && (lineHasTokens(out, "qdisc", "cake", "root") || lineHasTokens(out, "qdisc", "ingress")) {
		return fmt.Errorf("очереди на %s остались после удаления", item.Interface)
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "show", "dev", item.IFB); err == nil {
		return fmt.Errorf("интерфейс %s остался после удаления", item.IFB)
	}
	return nil
}

func sameOwnedLinks(left, right []ownedLink) bool {
	key := func(items []ownedLink) []string {
		result := make([]string, 0, len(items))
		for _, item := range items {
			result = append(result, item.WAN+"\x00"+item.Interface+"\x00"+item.IFB)
		}
		sort.Strings(result)
		return result
	}
	return reflect.DeepEqual(key(left), key(right))
}

func lineHasTokens(output string, tokens ...string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		fields := trafficFields(line)
		matched := true
		for _, token := range tokens {
			want := normalizeTrafficToken(token)
			found := false
			for _, field := range fields {
				if normalizeTrafficToken(field) == want {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func outputHasTokens(output string, tokens ...string) bool {
	fields := trafficFields(output)
	for _, token := range tokens {
		wanted := normalizeTrafficToken(token)
		found := false
		for _, field := range fields {
			if normalizeTrafficToken(field) == wanted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func trafficFields(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != ':' && r != '_' && r != '-'
	})
}

func normalizeTrafficToken(token string) string {
	text := strings.ToLower(token)
	units := []struct {
		suffix string
		factor float64
	}{{"gbit", 1_000_000}, {"mbit", 1_000}, {"kbit", 1}, {"bit", 0.001}}
	for _, unit := range units {
		if !strings.HasSuffix(text, unit.suffix) {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSuffix(text, unit.suffix), 64)
		if err == nil {
			return strconv.FormatFloat(value*unit.factor, 'f', -1, 64) + "kbit"
		}
	}
	return text
}

func missingTrafficObject(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no such") || strings.Contains(text, "not found") || strings.Contains(text, "cannot find") || strings.Contains(text, "handle of zero")
}

func (s *Subsystem) ownedPath() string { return filepath.Join(s.StateDir, "owned-qos.json") }

func (s *Subsystem) readOwned() ([]ownedLink, error) {
	data, err := os.ReadFile(s.ownedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []ownedLink
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("разбор списка QoS: %w", err)
	}
	return result, nil
}

func (s *Subsystem) writeOwned(items []ownedLink) error {
	if items == nil {
		items = []ownedLink{}
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.ownedPath(), append(data, '\n'), 0o600)
}
