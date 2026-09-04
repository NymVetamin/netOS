// Package policy owns the kernel ipsets used by domain-based channel rules.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const DomainSetTimeout = 300

type ownedSet struct {
	Policy     string `json:"policy"`
	Name       string `json:"name"`
	Family     string `json:"family"`
	Definition string `json:"definition"`
}

type Subsystem struct {
	Runner   system.Runner
	StateDir string
}

// CleanupSubsystem removes sets that are no longer referenced. It deliberately
// runs after firewall: ipset refuses to destroy a set while an iptables rule
// still refers to it.
type CleanupSubsystem struct {
	Runner   system.Runner
	StateDir string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir}
}

func NewCleanup(r system.Runner, stateDir string) *CleanupSubsystem {
	return &CleanupSubsystem{Runner: r, StateDir: stateDir}
}

func (s *Subsystem) Name() string        { return "policy" }
func (s *CleanupSubsystem) Name() string { return "policy-cleanup" }

func IPv4SetName(policyID string) string { return setName(policyID, "inet") }
func IPv6SetName(policyID string) string { return setName(policyID, "inet6") }

func setName(policyID, family string) string {
	hash := sha256.Sum256([]byte(policyID))
	suffix := "4"
	if family == "inet6" {
		suffix = "6"
	}
	return fmt.Sprintf("netos-p%s-%x", suffix, hash[:8])
}

func desiredSets(cfg *config.Config) []ownedSet {
	if cfg == nil {
		return nil
	}
	xrayServers := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if server.Type == "xray" {
			xrayServers[server.ID] = true
		}
	}
	var out []ownedSet
	for _, item := range cfg.Policies {
		if !item.Enabled || len(item.Domains) == 0 || xrayServers[item.VPNServer] {
			continue
		}
		domains := make([]string, 0, len(item.Domains))
		for _, raw := range item.Domains {
			domains = append(domains, strings.Trim(strings.ToLower(raw), "."))
		}
		sort.Strings(domains)
		digest := sha256.Sum256([]byte(strings.Join(domains, "\n")))
		out = append(out, ownedSet{
			Policy: item.ID, Name: IPv4SetName(item.ID), Family: "inet", Definition: fmt.Sprintf("%x", digest[:8]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func domainPoliciesEqual(a, b *config.Config) bool {
	selectPolicies := func(cfg *config.Config) []config.Policy {
		if cfg == nil {
			return nil
		}
		var out []config.Policy
		for _, item := range cfg.Policies {
			if len(item.Domains) > 0 {
				out = append(out, item)
			}
		}
		return out
	}
	return reflect.DeepEqual(selectPolicies(a), selectPolicies(b))
}

func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, next)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	before, after := desiredSets(old), desiredSets(next)
	if !reflect.DeepEqual(before, after) || !domainPoliciesEqual(old, next) {
		kind := "update"
		if len(before) == 0 && len(after) > 0 {
			kind = "create"
		} else if len(before) > 0 && len(after) == 0 {
			kind = "delete"
		}
		return []apply.Action{{Kind: kind, Target: "доменные политики", Detail: fmt.Sprintf("%d IPv4 ipset", len(after))}}, nil
	}
	if err := s.Health(ctx, next); err != nil {
		return []apply.Action{{Kind: "repair", Target: "доменные политики", Detail: err.Error()}}, nil
	}
	return nil, nil
}

func (s *Subsystem) ownedPath() string { return filepath.Join(s.StateDir, "owned-policy-ipsets.json") }

func validOwned(item ownedSet) bool {
	if (item.Family != "inet" && item.Family != "inet6") || item.Name != setName(item.Policy, item.Family) {
		return false
	}
	// Empty is the pre-fingerprint ownership format. It is safe because the set
	// name is still derived from policy/family; Apply migrates it by recreating
	// the set and writing the current definition.
	if item.Definition == "" {
		return true
	}
	if len(item.Definition) != 16 {
		return false
	}
	for _, char := range item.Definition {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func (s *Subsystem) readOwned() ([]ownedSet, error) {
	data, err := os.ReadFile(s.ownedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []ownedSet
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("чтение ownership доменных ipset: %w", err)
	}
	seen := map[string]bool{}
	for _, item := range items {
		if !validOwned(item) || seen[item.Name] {
			return nil, fmt.Errorf("ownership содержит небезопасный или повторный ipset %q", item.Name)
		}
		seen[item.Name] = true
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

// OwnedSetNames returns only ownership records whose deterministic names match
// their policy and family. The uninstaller uses it to avoid touching foreign
// kernel sets when state is malformed or has been tampered with.
func OwnedSetNames(stateDir string) ([]string, error) {
	items, err := (&Subsystem{StateDir: stateDir}).readOwned()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	return names, nil
}

func (s *Subsystem) writeOwned(items []ownedSet) error {
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(s.ownedPath(), append(data, '\n'), 0o600)
}

type stateSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func snapshotFile(path string) (stateSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return stateSnapshot{}, nil
	}
	if err != nil {
		return stateSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return stateSnapshot{}, fmt.Errorf("%s не является обычным файлом", path)
	}
	data, err := os.ReadFile(path)
	return stateSnapshot{exists: true, data: data, mode: info.Mode().Perm()}, err
}

func restoreFile(path string, snap stateSnapshot) error {
	if !snap.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return system.WriteFileAtomic(path, snap.data, snap.mode)
}

func parseSetNames(output string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			out[name] = true
		}
	}
	return out
}

func setHealthy(detail string, item ownedSet) bool {
	if !strings.Contains(detail, "Type: hash:ip") {
		return false
	}
	for _, line := range strings.Split(detail, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "Header:" {
			family, timeout := false, false
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "family" && fields[i+1] == item.Family {
					family = true
				}
				if fields[i] == "timeout" && fields[i+1] == fmt.Sprint(DomainSetTimeout) {
					timeout = true
				}
			}
			return family && timeout
		}
	}
	return false
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	desired := desiredSets(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	if len(desired) == 0 && len(owned) == 0 {
		return nil
	}
	if _, err := system.NewPackages(s.Runner).Ensure(ctx, "ipset"); err != nil {
		return fmt.Errorf("install ipset for domain policies: %w", err)
	}
	stateBefore, err := snapshotFile(s.ownedPath())
	if err != nil {
		return err
	}
	namesOut, err := s.Runner.Run(ctx, "ipset", "list", "-name")
	if err != nil {
		return fmt.Errorf("чтение ipset: %w", err)
	}
	live := parseSetNames(namesOut)
	ownedNames := map[string]bool{}
	ownedByName := map[string]ownedSet{}
	for _, item := range owned {
		ownedNames[item.Name] = true
		ownedByName[item.Name] = item
	}
	for _, item := range desired {
		if live[item.Name] && !ownedNames[item.Name] {
			return fmt.Errorf("ipset %s уже существует и не принадлежит netOS", item.Name)
		}
	}

	saved := map[string]string{}
	for _, item := range desired {
		name := item.Name
		if !live[name] || !ownedNames[name] {
			continue
		}
		data, err := s.Runner.Run(ctx, "ipset", "save", name)
		if err != nil {
			return fmt.Errorf("снимок ipset %s: %w", name, err)
		}
		if !strings.HasSuffix(data, "\n") {
			data += "\n"
		}
		saved[name] = data
	}
	mutated := map[string]bool{}
	rollback := func(cause error) error {
		var failures []string
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, name := range sortedNames(mutated) {
			if _, err := s.Runner.Run(rollbackCtx, "ipset", "destroy", name); err != nil && !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
				failures = append(failures, err.Error())
			}
		}
		var restore strings.Builder
		for _, name := range sortedNames(mutated) {
			restore.WriteString(saved[name])
		}
		if restore.Len() > 0 {
			if _, err := s.Runner.RunInput(rollbackCtx, restore.String(), "ipset", "restore"); err != nil {
				failures = append(failures, err.Error())
			}
		}
		if err := restoreFile(s.ownedPath(), stateBefore); err != nil {
			failures = append(failures, err.Error())
		}
		if len(failures) > 0 {
			return fmt.Errorf("%w; rollback ipset также не удался: %s", cause, strings.Join(failures, "; "))
		}
		return cause
	}

	for _, item := range desired {
		if live[item.Name] {
			detail, err := s.Runner.Run(ctx, "ipset", "list", item.Name)
			if err != nil {
				return rollback(err)
			}
			if setHealthy(detail, item) && ownedByName[item.Name].Definition == item.Definition {
				continue
			}
			mutated[item.Name] = true
			if _, err := s.Runner.Run(ctx, "ipset", "destroy", item.Name); err != nil {
				return rollback(err)
			}
		}
		mutated[item.Name] = true
		if _, err := s.Runner.Run(ctx, "ipset", "create", item.Name, "hash:ip", "family", item.Family, "timeout", fmt.Sprint(DomainSetTimeout)); err != nil {
			return rollback(err)
		}
	}
	// Retain stale ownership until policy-cleanup runs after firewall. New sets
	// must be recorded now so cleanup and rollback never mistake them for foreign.
	union := append(append([]ownedSet(nil), owned...), desired...)
	union = uniqueOwned(union)
	if err := s.writeOwned(union); err != nil {
		return rollback(err)
	}
	return nil
}

func sortedNames(items map[string]bool) []string {
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func uniqueOwned(items []ownedSet) []ownedSet {
	byName := make(map[string]ownedSet, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	out := make([]ownedSet, 0, len(byName))
	for _, item := range byName {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *CleanupSubsystem) ownedPath() string {
	return filepath.Join(s.StateDir, "owned-policy-ipsets.json")
}

func (s *CleanupSubsystem) Plan(_, _ *config.Config) ([]apply.Action, error) { return nil, nil }

func (s *CleanupSubsystem) Apply(ctx context.Context, cfg *config.Config) error {
	owner := &Subsystem{Runner: s.Runner, StateDir: s.StateDir}
	owned, err := owner.readOwned()
	if err != nil {
		return err
	}
	desired := desiredSets(cfg)
	if len(owned) == 0 && len(desired) == 0 {
		return nil
	}
	desiredNames := map[string]bool{}
	for _, item := range desired {
		desiredNames[item.Name] = true
	}
	var stale []ownedSet
	for _, item := range owned {
		if !desiredNames[item.Name] {
			stale = append(stale, item)
		}
	}
	stateBefore, err := snapshotFile(s.ownedPath())
	if err != nil {
		return err
	}
	saved := map[string]string{}
	for _, item := range stale {
		data, err := s.Runner.Run(ctx, "ipset", "save", item.Name)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
				continue
			}
			return fmt.Errorf("snapshot stale ipset %s: %w", item.Name, err)
		}
		if !strings.HasSuffix(data, "\n") {
			data += "\n"
		}
		saved[item.Name] = data
	}
	destroyed := map[string]bool{}
	rollback := func(cause error) error {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var failures []string
		for _, name := range sortedNames(destroyed) {
			if _, err := s.Runner.Run(rollbackCtx, "ipset", "destroy", name); err != nil && !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
				failures = append(failures, err.Error())
			}
		}
		var restore strings.Builder
		for _, name := range sortedNames(destroyed) {
			restore.WriteString(saved[name])
		}
		if restore.Len() > 0 {
			if _, err := s.Runner.RunInput(rollbackCtx, restore.String(), "ipset", "restore"); err != nil {
				failures = append(failures, err.Error())
			}
		}
		if err := restoreFile(s.ownedPath(), stateBefore); err != nil {
			failures = append(failures, err.Error())
		}
		if len(failures) > 0 {
			return fmt.Errorf("%w; policy cleanup rollback failed: %s", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	for _, item := range stale {
		if _, err := s.Runner.Run(ctx, "ipset", "destroy", item.Name); err != nil && !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return rollback(err)
		}
		destroyed[item.Name] = true
	}
	if err := owner.writeOwned(desired); err != nil {
		return rollback(err)
	}
	return nil
}

func (s *CleanupSubsystem) Health(context.Context, *config.Config) error { return nil }

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	desired := desiredSets(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(owned, desired) {
		return fmt.Errorf("ownership доменных ipset расходится с конфигурацией")
	}
	if len(desired) == 0 {
		return nil
	}
	namesOut, err := s.Runner.Run(ctx, "ipset", "list", "-name")
	if err != nil {
		return err
	}
	live := parseSetNames(namesOut)
	for _, item := range desired {
		if !live[item.Name] {
			return fmt.Errorf("ipset %s отсутствует", item.Name)
		}
		detail, err := s.Runner.Run(ctx, "ipset", "list", item.Name)
		if err != nil || !setHealthy(detail, item) {
			return fmt.Errorf("ipset %s имеет неверный type/family/timeout: %v", item.Name, err)
		}
	}
	return nil
}
