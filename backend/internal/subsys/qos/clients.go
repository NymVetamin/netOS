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
		if _, err := s.Runner.Run(ctx, "ip", "link", "show", "dev", item.Name); err != nil {
			return fmt.Errorf("интерфейс сегмента %s недоступен: %w", item.Name, err)
		}
	}
	for _, name := range previous {
		if !wanted[name] {
			if err := s.removeClientInterface(ctx, name); err != nil {
				return fmt.Errorf("удаление лимитов клиентов с %s: %w", name, err)
			}
		}
	}
	for _, item := range desired {
		if err := s.applyClientInterface(ctx, item); err != nil {
			if !containsString(previous, item.Name) {
				if cleanupErr := s.removeClientInterface(ctx, item.Name); cleanupErr != nil {
					recovery := append(append([]string(nil), previous...), item.Name)
					sort.Strings(recovery)
					stateErr := s.writeClientInterfaces(recovery)
					return fmt.Errorf("лимиты клиентов на %s: %w; уборка нового объекта: %v; сохранение ownership: %v", item.Name, err, cleanupErr, stateErr)
				}
			}
			return fmt.Errorf("лимиты клиентов на %s: %w", item.Name, err)
		}
	}
	names := make([]string, 0, len(desired))
	for _, item := range desired {
		names = append(names, item.Name)
	}
	if err := s.writeClientInterfaces(names); err != nil {
		var cleanupErrs []string
		for _, item := range desired {
			if !containsString(previous, item.Name) {
				if cleanupErr := s.removeClientInterface(ctx, item.Name); cleanupErr != nil {
					cleanupErrs = append(cleanupErrs, cleanupErr.Error())
				}
			}
		}
		if len(cleanupErrs) > 0 {
			return fmt.Errorf("%w; уборка после отказа записи ownership: %s", err, strings.Join(cleanupErrs, "; "))
		}
		return err
	}
	return nil
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
	if err := s.deleteClientQdisc(ctx, item.Name, "root"); err != nil {
		return err
	}
	if len(item.Download) == 0 {
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
	if err := s.deleteClientQdisc(ctx, item.Name, "ingress"); err != nil {
		return err
	}
	if len(item.Upload) == 0 {
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
	owned, err := s.readClientInterfaces()
	if err != nil {
		return err
	}
	desiredNames := make([]string, 0, len(items))
	for _, item := range items {
		desiredNames = append(desiredNames, item.Name)
	}
	sort.Strings(owned)
	if !equalStrings(owned, desiredNames) {
		return fmt.Errorf("список интерфейсов с лимитами клиентов не соответствует конфигурации")
	}
	for _, item := range items {
		out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", item.Name)
		if err != nil {
			return err
		}
		hasDownload := lineHasTokens(out, "qdisc", "htb", "root", "1:")
		hasUpload := lineHasTokens(out, "qdisc", "ingress")
		if len(item.Download) > 0 && !hasDownload {
			return fmt.Errorf("ограничение загрузки на %s не работает", item.Name)
		}
		if len(item.Download) == 0 && hasDownload {
			return fmt.Errorf("на %s осталось лишнее ограничение загрузки", item.Name)
		}
		if len(item.Upload) > 0 && !hasUpload {
			return fmt.Errorf("ограничение отдачи на %s не работает", item.Name)
		}
		if len(item.Upload) == 0 && hasUpload {
			return fmt.Errorf("на %s осталось лишнее ограничение отдачи", item.Name)
		}
		if len(item.Download) > 0 {
			classes, err := s.Runner.Run(ctx, "tc", "class", "show", "dev", item.Name)
			if err != nil {
				return err
			}
			filters, err := s.Runner.Run(ctx, "tc", "filter", "show", "dev", item.Name, "parent", "1:")
			if err != nil {
				return err
			}
			expectedClasses := []string{"1:1"}
			expectedMACs := make([]string, 0, len(item.Download))
			for index, client := range item.Download {
				classID := fmt.Sprintf("1:%d", index+10)
				expectedClasses = append(expectedClasses, classID)
				expectedMACs = append(expectedMACs, strings.ToLower(client.MAC))
				if !blockHasTokens(classes, "class ", "class", "htb", classID, "rate", fmt.Sprintf("%dkbit", client.DownKbit)) ||
					!blockHasTokens(filters, "filter ", "pref", fmt.Sprint(100+index), "dst_mac", strings.ToLower(client.MAC), "classid", classID) {
					return fmt.Errorf("лимит загрузки клиента %s на %s не соответствует конфигурации", client.MAC, item.Name)
				}
			}
			sort.Strings(expectedClasses)
			sort.Strings(expectedMACs)
			if !equalStrings(htbClassIDs(classes), expectedClasses) || !equalStrings(valuesAfterToken(filters, "dst_mac"), expectedMACs) {
				return fmt.Errorf("на %s остались лишние классы или фильтры загрузки", item.Name)
			}
		}
		if len(item.Upload) > 0 {
			filters, err := s.Runner.Run(ctx, "tc", "filter", "show", "dev", item.Name, "parent", "ffff:")
			if err != nil {
				return err
			}
			expectedMACs := make([]string, 0, len(item.Upload))
			for index, client := range item.Upload {
				expectedMACs = append(expectedMACs, strings.ToLower(client.MAC))
				if !blockHasTokens(filters, "filter ", "pref", fmt.Sprint(100+index), "src_mac", strings.ToLower(client.MAC), "police", "rate", fmt.Sprintf("%dkbit", client.UpKbit)) {
					return fmt.Errorf("лимит отдачи клиента %s на %s не соответствует конфигурации", client.MAC, item.Name)
				}
			}
			sort.Strings(expectedMACs)
			if !equalStrings(valuesAfterToken(filters, "src_mac"), expectedMACs) {
				return fmt.Errorf("на %s остались лишние фильтры отдачи", item.Name)
			}
		}
	}
	return nil
}

func (s *Subsystem) removeClientInterface(ctx context.Context, name string) error {
	for _, kind := range []string{"root", "ingress"} {
		if err := s.deleteClientQdisc(ctx, name, kind); err != nil {
			return err
		}
	}
	if out, err := s.Runner.Run(ctx, "tc", "qdisc", "show", "dev", name); err == nil && (lineHasTokens(out, "qdisc", "htb", "root") || lineHasTokens(out, "qdisc", "ingress")) {
		return fmt.Errorf("очереди лимитов на %s остались после удаления", name)
	}
	return nil
}

func (s *Subsystem) deleteClientQdisc(ctx context.Context, name, kind string) error {
	if _, err := s.Runner.Run(ctx, "tc", "qdisc", "del", "dev", name, kind); err != nil && !missingTrafficObject(err) {
		return err
	}
	return nil
}

func containsString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func valuesAfterToken(output, token string) []string {
	fields := trafficFields(output)
	var result []string
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == token {
			result = append(result, fields[i+1])
		}
	}
	sort.Strings(result)
	return result
}

func htbClassIDs(output string) []string {
	var result []string
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		fields := trafficFields(line)
		if len(fields) >= 3 && fields[0] == "class" && fields[1] == "htb" {
			result = append(result, fields[2])
		}
	}
	sort.Strings(result)
	return result
}

func blockHasTokens(output, boundary string, tokens ...string) bool {
	var blocks []string
	var current strings.Builder
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, boundary) && current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
		if trimmed != "" {
			current.WriteByte(' ')
			current.WriteString(trimmed)
		}
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}
	for _, block := range blocks {
		fields := trafficFields(block)
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
	return s.writeFile(s.clientOwnedPath(), append(data, '\n'), 0o600)
}
