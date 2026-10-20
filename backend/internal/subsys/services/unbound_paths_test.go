package services

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	for _, want := range []string{`directory: "/var/lib/unbound/netos"`, `auto-trust-anchor-file: "/var/lib/unbound/netos/root.key"`, `include: "/etc/unbound/netos-blocklist.conf"`} {
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

func TestUnboundAnchorMigrationPrefersRecentPath(t *testing.T) {
	useProviderPaths(t)
	prior, legacy := priorUnboundAnchorPath, legacyUnboundAnchorPath
	t.Cleanup(func() { priorUnboundAnchorPath, legacyUnboundAnchorPath = prior, legacy })
	root := t.TempDir()
	priorUnboundAnchorPath, legacyUnboundAnchorPath = filepath.Join(root, "prior.key"), filepath.Join(root, "legacy.key")
	unboundAnchorPath = filepath.Join(root, "netos", "root.key")
	for path, content := range map[string]string{priorUnboundAnchorPath: "recent RFC5011 state", legacyUnboundAnchorPath: "older RFC5011 state"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := newProviderRunner()
	if err := NewUnbound(r).ensureTrustAnchor(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(unboundAnchorPath)
	if string(data) != "recent RFC5011 state" || hasCommand(r.commands, "unbound-anchor") {
		t.Fatal("recent state lost or bootstrapped again")
	}
	info, err := os.Stat(filepath.Dir(unboundAnchorPath))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Fatalf("unsafe directory: %v", err)
	}
}

func TestUnboundRejectsSymlinkStateDirectory(t *testing.T) {
	useProviderPaths(t)
	root := t.TempDir()
	target := filepath.Join(root, "foreign")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "netos")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	unboundAnchorPath = filepath.Join(link, "root.key")
	if err := ensureUnboundStateDir(); err == nil {
		t.Fatal("symlink directory accepted")
	}
	info, _ := os.Stat(target)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
		t.Fatal("foreign directory modified")
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
