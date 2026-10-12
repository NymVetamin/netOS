package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Capture production paths before TestMain redirects every write to a sandbox.
var shippedUnboundPaths = []string{unboundConfPath, unboundBlocklistPath, unboundAnchorPath}

func TestUnboundUsesDebianAppArmorLocations(t *testing.T) {
	for _, path := range shippedUnboundPaths[:2] {
		// Debian profile: /etc/unbound/** r. The distro daemon includes
		// unbound.conf.d/*.conf, which must not pick up our standalone server.
		if !strings.HasPrefix(path, "/etc/unbound/") || strings.Contains(path, "/unbound.conf.d/") {
			t.Fatalf("config outside profile or imported by distro service: %s", path)
		}
	}
	if !strings.HasPrefix(shippedUnboundPaths[2], "/var/lib/unbound/") {
		t.Fatal("DNSSEC state outside AppArmor write rules")
	}
	useProviderPaths(t)
	unboundConfPath, unboundBlocklistPath, unboundAnchorPath = shippedUnboundPaths[0], shippedUnboundPaths[1], shippedUnboundPaths[2]
	cfg := resolverConfig()
	cfg.DNS.DNSSEC = true
	cfg.DNS.Blocklists = []config.Blocklist{{Enabled: true, URL: "https://example.test/hosts"}}
	out := NewUnbound(nil).Render(cfg)
	for _, want := range []string{`directory: "/var/lib/unbound"`, `auto-trust-anchor-file: "/var/lib/unbound/netos-root.key"`, `include: "/etc/unbound/netos-blocklist.conf"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing permitted path %s", want)
		}
	}
	if strings.Contains(out, "/var/lib/netos") {
		t.Fatal("runtime still accesses blocked netOS directory")
	}
	if !strings.Contains(unboundUnitContent(), "-c /etc/unbound/netos.conf") {
		t.Fatal("unit uses old config location")
	}
}

func TestUnboundAnchorMigrationPreservesExistingState(t *testing.T) {
	useProviderPaths(t)
	old := legacyUnboundAnchorPath
	legacyUnboundAnchorPath = filepath.Join(t.TempDir(), "old.key")
	t.Cleanup(func() { legacyUnboundAnchorPath = old })
	data := []byte("; RFC5011 state\n. IN DNSKEY 257 3 8 test\n")
	if err := os.WriteFile(legacyUnboundAnchorPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	unboundAnchorPath = filepath.Join(t.TempDir(), "new-state", "netos-root.key")
	r := newProviderRunner()
	u := NewUnbound(r)
	if err := u.ensureTrustAnchor(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(unboundAnchorPath)
	if err != nil || string(got) != string(data) {
		t.Fatalf("anchor not migrated: %q %v", got, err)
	}
	if hasCommand(r.commands, "unbound-anchor") {
		t.Fatal("migration unnecessarily contacts the network")
	}
	if err := os.WriteFile(unboundAnchorPath, []byte("newer state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := u.ensureTrustAnchor(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(unboundAnchorPath)
	if string(got) != "newer state" {
		t.Fatal("new anchor overwritten by stale legacy anchor")
	}
}
