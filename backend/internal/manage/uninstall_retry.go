package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// A previous uninstall may have purged iptables before losing its SSH session.
// Missing tools alone never prove that firewall restoration succeeded. Allow
// retry only for an empty baseline and a verifiably permissive current firewall.
func (m *Manager) uninstallFirewallAlreadyRestored(ctx context.Context, b *systemBaseline, cause error) bool {
	if b == nil || strings.TrimSpace(b.IPTables4) != "" || strings.TrimSpace(b.IPTables6) != "" ||
		(!errors.Is(cause, exec.ErrNotFound) && !errors.Is(cause, os.ErrNotExist)) {
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
