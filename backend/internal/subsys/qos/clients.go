package qos

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type clientInterface struct {
	Name     string          `json:"name"`
	Download []config.Client `json:"-"`
	Upload   []config.Client `json:"-"`
}

func (s *Subsystem) applyClients(ctx context.Context, cfg *config.Config) error {
	previous, err := s.readClientInterfaces()
	if err != nil {
		return err
	}
	desired, err := desiredClientInterfaces(cfg)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, item := range desired {
		wanted[item.Name] = true
	}
	for _, name := range previous {
		if !wanted[name] {
			s.removeClientInterface(ctx, name)
		}
	}
	for _, item := range desired {
		if _, err := s.Runner.Run(ctx, "ip", "link", "show", "dev", item.Name); err != nil {
			return fmt.Errorf("интерфейс сегмента %s недоступен: %w", item.Name, err)
		}
		if err := s.applyClientInterface(ctx, item); err != nil {
			return fmt.Errorf("лимиты клиентов на %s: %w", item.Name, err)
		}
	}
	names := make([]string, 0, len(desired))
	for _, item := range desired {
		names = append(names, item.Name)
	}
	return s.writeClientInterfaces(names)
}

func desiredClientInterfaces(cfg *config.Config) ([]clientInterface, error) {
	linkNames := map[string]string{}
	for _, item := range cfg.Interfaces {
		linkNames[item.ID] = item.Name
	}
	networkLinks := map[string]string{}
	for _, network := range cfg.Networks {
		if network.Enabled {
			networkLinks[network.ID] = linkNames[network.Interface]
		}
	}
	byName := map[string]*clientInterface{}
	for _, client := range cfg.Clients {
		if client.DownKbit == 0 && client.UpKbit == 0 {
			continue
		}
		name := networkLinks[client.Network]
		if name == "" {
			return nil, fmt.Errorf("для клиента %s не найден интерфейс сегмента", client.MAC)
		}
		item := byName[name]
		if item == nil {
			item = &clientInterface{Name: name}
			byName[name] = item
		}
		if client.DownKbit > 0 {
			item.Download = append(item.Download, client)
		}
		if client.UpKbit > 0 {
			item.Upload = append(item.Upload, client)
		}
	}
	result := make([]clientInterface, 0, len(byName))
	for _, item := range byName {
		sort.Slice(item.Download, func(i, j int) bool { return item.Download[i].MAC < item.Download[j].MAC })
		sort.Slice(item.Upload, func(i, j int) bool { return item.Upload[i].MAC < item.Upload[j].MAC })
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *Subsystem) applyClientInterface(ctx context.Context, item clientInterface) error {
	if len(item.Download) == 0 {
		_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", item.Name, "root")
	} else {
		if _, err := s.Runner.Run(ctx, "tc", "qdisc", "replace", "dev", item.Name, "root", "handle", "1:", "htb", "default", "1"); err != nil {
			return err
		}
		if _, err := s.Runner.Run(ctx, "tc", "class", "replace", "dev", item.Name, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit", "ceil", "10gbit"); err != nil {
			return err
		}
		for index, client := range item.Download {
			minor := index + 10
			classID := fmt.Sprintf("1:%d", minor)
			rate := fmt.Sprintf("%dkbit", client.DownKbit)
			if _, err := s.Runner.Run(ctx, "tc", "class", "replace", "dev", item.Name, "parent", "1:1", "classid", classID, "htb", "rate", rate, "ceil", rate, "burst", "32k"); err != nil {
				return err
			}
			if _, err := s.Runner.Run(ctx, "tc", "filter", "replace", "dev", item.Name, "parent", "1:", "protocol", "all", "pref", fmt.Sprint(100+index), "flower", "dst_mac", client.MAC, "classid", classID); err != nil {
				return err
			}
		}
	}
	if len(item.Upload) == 0 {
		_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", item.Name, "ingress")
	} else {
		if _, err := s.Runner.Run(ctx, "tc", "qdisc", "replace", "dev", item.Name, "handle", "ffff:", "ingress"); err != nil {
			return err
		}
		for index, client := range item.Upload {
			if _, err := s.Runner.Run(ctx, "tc", "filter", "replace", "dev", item.Name, "parent", "ffff:", "protocol", "all", "pref", fmt.Sprint(100+index), "flower", "src_mac", client.MAC, "action", "police", "rate", fmt.Sprintf("%dkbit", client.UpKbit), "burst", "64k", "conform-exceed", "drop"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Subsystem) healthClients(ctx context.Context, cfg *config.Config) error {
	items, err := desiredClientInterfaces(cfg)
	if err != nil {
		return err
	}
	for _, item := range items {
		out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", item.Name)
		if err != nil {
			return err
		}
		if len(item.Download) > 0 && !strings.Contains(out, "htb") {
			return fmt.Errorf("ограничение загрузки на %s не работает", item.Name)
		}
		if len(item.Upload) > 0 && !strings.Contains(out, "ingress") {
			return fmt.Errorf("ограничение отдачи на %s не работает", item.Name)
		}
	}
	return nil
}

func (s *Subsystem) removeClientInterface(ctx context.Context, name string) {
	_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", name, "root")
	_, _ = s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", name, "ingress")
}

func (s *Subsystem) clientOwnedPath() string {
	return filepath.Join(s.StateDir, "owned-qos-clients.json")
}

func (s *Subsystem) readClientInterfaces() ([]string, error) {
	data, err := os.ReadFile(s.clientOwnedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Subsystem) writeClientInterfaces(names []string) error {
	if names == nil {
		names = []string{}
	}
	data, err := json.MarshalIndent(names, "", "  ")
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(s.clientOwnedPath(), append(data, '\n'), 0o600)
}
