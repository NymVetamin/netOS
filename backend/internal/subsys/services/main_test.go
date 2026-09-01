package services

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps every package test away from the host's real service files.
// Individual tests may temporarily replace these paths and restore them to this
// sandbox, so even a root Linux race sweep cannot mutate the running router.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "netos-services-tests-")
	if err != nil {
		panic(err)
	}
	systemdUnitDir = filepath.Join(root, "systemd")
	dnsmasqConfPath, dnsmasqLeasePath = filepath.Join(root, "dnsmasq.conf"), filepath.Join(root, "dnsmasq.leases")
	iscConfPath, iscLeasePath = filepath.Join(root, "dhcpd.conf"), filepath.Join(root, "dhcpd.leases")
	keaConfPath, keaLeasePath = filepath.Join(root, "kea.json"), filepath.Join(root, "kea-leases.csv")
	unboundConfPath, unboundAnchorPath = filepath.Join(root, "unbound.conf"), filepath.Join(root, "root.key")
	dnsproxyConfPath, dnsproxyHostsPath, dnsproxyBinary = filepath.Join(root, "dnsproxy.yaml"), filepath.Join(root, "dnsproxy-hosts"), filepath.Join(root, "dnsproxy")
	blocklistCacheDir = filepath.Join(root, "blocklists")
	dnsmasqBlocklistPath = filepath.Join(root, "dnsmasq-blocklist.conf")
	unboundBlocklistPath = filepath.Join(root, "unbound-blocklist.conf")
	dnsproxyBlocklistPath = filepath.Join(root, "dnsproxy-blocklist.hosts")
	systemResolverRoot = root

	code := m.Run()
	if err := os.RemoveAll(root); err != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}
