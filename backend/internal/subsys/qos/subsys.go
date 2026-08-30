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
	"strings"

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
	Runner   system.Runner
	StateDir string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir}
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
	if reflect.DeepEqual(before, next.QoS) && reflect.DeepEqual(oldClients, next.Clients) {
		return nil, nil
	}
	kind := "update"
	if next.QoS.Enabled && !before.Enabled {
		kind = "create"
	} else if !next.QoS.Enabled {
		kind = "delete"
	}
	return []apply.Action{{Subsystem: s.Name(), Kind: kind, Target: "очереди трафика", Detail: "CAKE на интернет-каналах", Disruptive: true}}, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	previous, err := s.readOwned()
	if err != nil {
		return err
	}
	if !cfg.QoS.Enabled {
		for _, item := range previous {
			s.remove(ctx, item)
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
			s.remove(ctx, item)
		}
	}

	settings := map[string]config.QoSWAN{}
	for _, item := range cfg.QoS.WANs {
		settings[item.WAN] = item
	}
	for _, item := range wanted {
		if err := s.applyLink(ctx, item, settings[item.WAN], ownedIFB[item.IFB]); err != nil {
			return fmt.Errorf("QoS %s: %w", item.WAN, err)
		}
	}
	if err := s.writeOwned(wanted); err != nil {
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
	if !cfg.QoS.Enabled {
		return s.healthClients(ctx, cfg)
	}
	links, err := desiredLinks(cfg)
	if err != nil {
		return err
	}
	for _, item := range links {
		for _, dev := range []string{item.Interface, item.IFB} {
			out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", dev)
			if err != nil || !strings.Contains(out, "cake") {
				return fmt.Errorf("очередь CAKE на %s не работает", dev)
			}
		}
	}
	return s.healthClients(ctx, cfg)
}

func (s *Subsystem) remove(ctx context.Context, item ownedLink) {
	_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", item.Interface, "root")
	_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", item.Interface, "ingress")
	_, _ = s.Runner.Run(ctx, "ip", "link", "del", "dev", item.IFB)
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
	return system.WriteFileAtomic(s.ownedPath(), append(data, '\n'), 0o600)
}
