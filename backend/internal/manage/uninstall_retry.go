package manage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

const uninstallFirewallCheckpoint = systemBaselineDir + "/uninstall-firewall-restored"

// Any subsequent real Apply invalidates the completed uninstall phase before
// it can recreate netOS rules. Read-only commands and previews leave it alone.
func InvalidateUninstallCheckpoint(root string) error {
	err := os.Remove(rooted(root, uninstallFirewallCheckpoint))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func firewallCheckpointDigest(b *systemBaseline) string {
	data, _ := json.Marshal(b)
	return fmt.Sprintf("%x\n", sha256.Sum256(data))
}

func (m *Manager) recordUninstallFirewallRestored(b *systemBaseline) error {
	if b == nil {
		return nil
	}
	path := m.sys(uninstallFirewallCheckpoint)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return system.WriteFileAtomic(path, []byte("v2 "+firewallCheckpointDigest(b)), 0600)
}

func permissiveFirewallDump(dump string) bool {
	inTable := false
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") && !inTable && len(strings.Fields(line)) == 1 {
			inTable = true
			continue
		}
		if line == "COMMIT" && inTable {
			inTable = false
			continue
		}
		fields := strings.Fields(line)
		if inTable && len(fields) == 3 && strings.HasPrefix(fields[0], ":") && fields[1] == "ACCEPT" && strings.HasPrefix(fields[2], "[") && strings.HasSuffix(fields[2], "]") {
			continue
		}
		return false
	}
	return !inTable
}

func legacyRestoredAllTables(snapshot string, ipv4 bool) bool {
	if strings.TrimSpace(snapshot) == "" {
		return ipv4 // Only the old IPv4 default also cleared mangle.
	}
	filter, nat, mangle := missingFirewallTables(snapshot, ipv4)
	return filter == "" && nat == "" && mangle == ""
}

func (m *Manager) uninstallFirewallFailure(ctx context.Context, b *systemBaseline, stage string, cause error) error {
	if m.uninstallFirewallAlreadyRestored(ctx, b, cause) {
		return nil
	}
	if errors.Is(cause, exec.ErrNotFound) || errors.Is(cause, os.ErrNotExist) {
		return fmt.Errorf("%s: восстановление firewall не подтверждено; восстановите отсутствующую утилиту и повторите удаление: %w", stage, cause)
	}
	return fmt.Errorf("%s: %w", stage, cause)
}

// A previous uninstall may have purged iptables before losing its SSH session.
// Missing tools alone never prove that firewall restoration succeeded. Allow
// retry only for an empty baseline and a verifiably permissive current firewall.
func (m *Manager) uninstallFirewallAlreadyRestored(ctx context.Context, b *systemBaseline, cause error) bool {
	if b == nil ||
		(!errors.Is(cause, exec.ErrNotFound) && !errors.Is(cause, os.ErrNotExist)) {
		return false
	}
	// A completed restore is durable before package purge. A retry must not
	// require a utility that the same uninstall successfully purged. The digest
	// binds the checkpoint to this baseline; a later Apply removes it.
	if data, err := os.ReadFile(m.sys(uninstallFirewallCheckpoint)); err == nil {
		digest := firewallCheckpointDigest(b)
		stored, versioned := strings.CutPrefix(string(data), "v2 ")
		if stored == digest {
			return versioned || (legacyRestoredAllTables(b.IPTables4, true) && (!b.IPTables6Exists || legacyRestoredAllTables(b.IPTables6, false)))
		}
	}
	if !permissiveFirewallDump(b.IPTables4) || !permissiveFirewallDump(b.IPTables6) {
		return false
	}
	for _, path := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names", "/proc/net/eb_tables_names"} {
		data, err := os.ReadFile(m.sys(path))
		if (err != nil && !os.IsNotExist(err)) || strings.TrimSpace(string(data)) != "" {
			return false
		}
	}
	out, err := m.Output(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return false
	}
	var state struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &state) != nil || state.Objects == nil {
		return false
	}
	for _, object := range state.Objects {
		if _, exists := object["rule"]; exists {
			return false
		}
		if raw, exists := object["chain"]; exists {
			var chain struct {
				Policy string `json:"policy"`
			}
			if json.Unmarshal(raw, &chain) != nil || (chain.Policy != "" && chain.Policy != "accept") {
				return false
			}
		}
	}
	return true
}
