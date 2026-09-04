package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type outputVersionRunner struct{ output string }

func (r outputVersionRunner) Run(context.Context, string, ...string) (string, error) {
	return r.output, nil
}

type blockingVersionRunner struct{}

func (blockingVersionRunner) Run(ctx context.Context, _ string, _ ...string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func (r blockingVersionRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type fileVersionRunner struct {
	target string
	old    string
	new    string
}

func (r fileVersionRunner) Run(context.Context, string, ...string) (string, error) {
	data, err := os.ReadFile(r.target)
	if err != nil {
		return "", err
	}
	if string(data) == "new binary" {
		return r.new, nil
	}
	return r.old, nil
}

func (r fileVersionRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r outputVersionRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestVersionOutputMatchesExactVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		version string
		want    bool
	}{
		{name: "plain", output: "Xray 26.7.28", version: "v26.7.28", want: true},
		{name: "tag", output: "dnsproxy v0.84.0 linux/amd64", version: "v0.84.0", want: true},
		{name: "prefix collision", output: "Xray 126.7.28", version: "v26.7.28"},
		{name: "suffix collision", output: "Xray 26.7.280", version: "v26.7.28"},
		{name: "embedded token", output: "build-26.7.28beta", version: "v26.7.28"},
		{name: "prerelease suffix", output: "Xray 26.7.28-beta", version: "v26.7.28"},
		{name: "build suffix", output: "Xray 26.7.28+custom", version: "v26.7.28"},
		{name: "empty wanted", output: "anything", version: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionOutputMatches(tc.output, tc.version); got != tc.want {
				t.Fatalf("versionOutputMatches(%q, %q)=%v, want %v", tc.output, tc.version, got, tc.want)
			}
		})
	}
}

func TestCatalogMetadataAndExternalReleaseIntegrity(t *testing.T) {
	ids := map[string]bool{}
	targets := map[string]string{}
	packageOwners := map[string][]string{}
	for _, info := range config.Catalog {
		if info.ID == "" || info.Title == "" || info.Group == "" || info.Description == "" || info.SizeHint == "" {
			t.Errorf("incomplete catalog metadata: %+v", info)
		}
		if ids[info.ID] {
			t.Errorf("duplicate component ID %q", info.ID)
		}
		ids[info.ID] = true
		lookedUp, ok := config.ComponentByID(info.ID)
		if !ok || lookedUp.ID != info.ID {
			t.Errorf("ComponentByID(%q) failed: %+v, %v", info.ID, lookedUp, ok)
		}
		if info.External == (len(info.Packages) > 0) {
			t.Errorf("component %s must use exactly one installation source: external=%v packages=%v", info.ID, info.External, info.Packages)
		}
		seenPackages := map[string]bool{}
		for _, pkg := range info.Packages {
			if pkg == "" || seenPackages[pkg] {
				t.Errorf("component %s has empty/duplicate package %q", info.ID, pkg)
			}
			seenPackages[pkg] = true
			packageOwners[pkg] = append(packageOwners[pkg], info.ID)
		}
		for _, unit := range append(append([]string(nil), info.Units...), info.RunUnits...) {
			if !strings.HasSuffix(unit, ".service") {
				t.Errorf("component %s has invalid unit pattern %q", info.ID, unit)
			}
		}
		if !info.External {
			continue
		}
		rel, ok := externalReleases[info.ID]
		if !ok {
			t.Errorf("external component %s has no pinned release", info.ID)
			continue
		}
		if rel.Version == "" || rel.URL == nil || rel.FileInArchive == "" || len(rel.VersionArgs) == 0 || !path.IsAbs(rel.Target) {
			t.Errorf("incomplete release for %s: %+v", info.ID, rel)
		}
		if previous := targets[rel.Target]; previous != "" {
			t.Errorf("components %s and %s share external target %s", previous, info.ID, rel.Target)
		}
		targets[rel.Target] = info.ID
		for _, arch := range []string{"amd64", "arm64"} {
			sha := rel.SHA256[arch]
			decoded, err := hex.DecodeString(sha)
			if err != nil || len(decoded) != sha256.Size {
				t.Errorf("release %s/%s has invalid SHA-256 %q", info.ID, arch, sha)
			}
			download := rel.URL(rel.Version, arch)
			if !strings.HasPrefix(download, "https://") || !strings.Contains(download, rel.Version) {
				t.Errorf("release %s/%s has invalid URL %q", info.ID, arch, download)
			}
		}
	}
	for id := range externalReleases {
		if !ids[id] {
			t.Errorf("orphan external release %q", id)
		}
	}
	for pkg, owners := range packageOwners {
		if len(owners) > 1 && !(pkg == "ppp" && len(owners) == 2) {
			t.Errorf("unreviewed shared package %s: %v", pkg, owners)
		}
	}
}

func TestExternalComponentStateDistinguishesOutdatedBinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := externalReleases
	externalReleases = map[string]externalRelease{
		"tool": {Version: "v2.0.0", Target: target, VersionArgs: []string{"version"}},
	}
	if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { externalReleases = original })

	s := New(fileVersionRunner{target: target, old: "tool 1.0.0", new: "tool 2.0.0"}, testLogger{})
	anyInstalled, allInstalled := s.componentState(context.Background(), config.ComponentInfo{ID: "tool", External: true})
	if !anyInstalled || allInstalled {
		t.Fatalf("outdated binary state: any=%v all=%v", anyInstalled, allInstalled)
	}
}

func TestComponentStateRequiresStockUnitsDisabled(t *testing.T) {
	runner := &disableFailureRunner{}
	s := New(runner, testLogger{})
	anyInstalled, allInstalled := s.componentState(context.Background(), config.ComponentInfo{
		ID: "daemon", Packages: []string{"daemon"}, Units: []string{"daemon.service"},
	})
	if !anyInstalled || allInstalled {
		t.Fatalf("active stock unit state: any=%v all=%v", anyInstalled, allInstalled)
	}
	if !s.componentRemovable(context.Background(), config.ComponentInfo{
		ID: "daemon", Packages: []string{"shared"}, Units: []string{"daemon.service"},
	}, map[string]bool{"shared": true}) {
		t.Fatal("active stock unit was ignored when every package was shared")
	}
}

func TestPlanAndApplyReinstallOutdatedExternalBinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := tarGz(t, "tool", []byte("new binary"))
	sum := sha256.Sum256(archive)

	originalCatalog := config.Catalog
	originalReleases := externalReleases
	originalFetch := fetch
	config.Catalog = []config.ComponentInfo{{ID: "tool", Title: "Tool", External: true}}
	externalReleases = map[string]externalRelease{
		"tool": {
			Version:       "v2.0.0",
			URL:           func(string, string) string { return "https://example.invalid/tool.tar.gz" },
			SHA256:        map[string]string{runtime.GOARCH: hex.EncodeToString(sum[:])},
			FileInArchive: "tool",
			Target:        target,
			VersionArgs:   []string{"version"},
		},
	}
	if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	fetched := false
	fetch = func(context.Context, string) ([]byte, error) {
		fetched = true
		return archive, nil
	}
	t.Cleanup(func() {
		config.Catalog = originalCatalog
		externalReleases = originalReleases
		fetch = originalFetch
	})

	s := New(fileVersionRunner{target: target, old: "tool 1.0.0", new: "tool 2.0.0"}, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "tool", Installed: true}}}
	actions, err := s.Plan(&config.Config{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Kind != "create" {
		t.Fatalf("outdated binary was not planned for reinstall: %#v", actions)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !fetched {
		t.Fatal("outdated binary did not trigger release download")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new binary" {
		t.Fatalf("target was not atomically replaced: %q", got)
	}
	mark, err := os.ReadFile(externalOwnerPath(externalReleases["tool"]))
	if err != nil || string(mark) != externalOwnerMark {
		t.Fatalf("ownership marker missing: %q, %v", mark, err)
	}
}

func TestInstallExternalRejectsBinaryThatCannotReportPinnedVersion(t *testing.T) {
	archive := tarGz(t, "tool", []byte("new binary"))
	sum := sha256.Sum256(archive)
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	originalReleases := externalReleases
	originalFetch := fetch
	externalReleases = map[string]externalRelease{
		"tool": {
			Version: "v2.0.0", URL: func(string, string) string { return "https://example.invalid/tool" },
			SHA256: map[string]string{runtime.GOARCH: hex.EncodeToString(sum[:])}, FileInArchive: "tool",
			Target: target, VersionArgs: []string{"version"},
		},
	}
	if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
	t.Cleanup(func() {
		externalReleases = originalReleases
		fetch = originalFetch
	})
	s := New(outputVersionRunner{output: "tool 1.0.0"}, testLogger{})
	err := s.installExternal(context.Background(), config.ComponentInfo{ID: "tool", External: true})
	if err == nil || !strings.Contains(err.Error(), "v2.0.0") {
		t.Fatalf("invalid installed binary was accepted: %v", err)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || string(got) != "old binary" {
		t.Fatalf("previous binary was not restored: %q (%v)", got, readErr)
	}
	if _, statErr := os.Stat(target + ".netos-rollback"); !os.IsNotExist(statErr) {
		t.Fatalf("rollback artifact remains: %v", statErr)
	}
}

func TestInstallExternalRemovesInvalidFirstInstallation(t *testing.T) {
	archive := tarGz(t, "tool", []byte("invalid binary"))
	sum := sha256.Sum256(archive)
	target := filepath.Join(t.TempDir(), "tool")
	originalReleases := externalReleases
	originalFetch := fetch
	externalReleases = map[string]externalRelease{
		"tool": {
			Version: "v2.0.0", URL: func(string, string) string { return "https://example.invalid/tool" },
			SHA256: map[string]string{runtime.GOARCH: hex.EncodeToString(sum[:])}, FileInArchive: "tool",
			Target: target, VersionArgs: []string{"version"},
		},
	}
	fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
	t.Cleanup(func() {
		externalReleases = originalReleases
		fetch = originalFetch
	})
	s := New(outputVersionRunner{output: "tool 1.0.0"}, testLogger{})
	if err := s.installExternal(context.Background(), config.ComponentInfo{ID: "tool", External: true}); err == nil {
		t.Fatal("invalid first installation was accepted")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("invalid first installation remains: %v", err)
	}
}

func TestApplyReportsExternalInstallFailure(t *testing.T) {
	originalCatalog := config.Catalog
	originalReleases := externalReleases
	originalFetch := fetch
	config.Catalog = []config.ComponentInfo{{ID: "tool", Title: "Tool", External: true}}
	externalReleases = map[string]externalRelease{
		"tool": {
			Version: "v1.0.0", URL: func(string, string) string { return "https://example.invalid/tool" },
			SHA256: map[string]string{runtime.GOARCH: strings.Repeat("0", 64)}, FileInArchive: "tool",
			Target: filepath.Join(t.TempDir(), "tool"), VersionArgs: []string{"version"},
		},
	}
	fetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("network down") }
	t.Cleanup(func() {
		config.Catalog = originalCatalog
		externalReleases = originalReleases
		fetch = originalFetch
	})
	s := New(outputVersionRunner{}, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "tool", Installed: true}}}
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "Tool") {
		t.Fatalf("external install failure was hidden: %v", err)
	}
}

type disableFailureRunner struct{ aptCalled bool }

func (r *disableFailureRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	switch name {
	case "dpkg-query":
		return "install ok installed", nil
	case "systemctl":
		if len(args) > 0 && args[0] == "is-active" {
			return "active", nil
		}
		if len(args) > 0 && args[0] == "disable" {
			return "", errors.New("permission denied")
		}
	case "apt-get":
		r.aptCalled = true
	}
	return "", nil
}

func (r *disableFailureRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestInstallPropagatesStockUnitDisableFailure(t *testing.T) {
	runner := &disableFailureRunner{}
	s := New(runner, testLogger{})
	err := s.install(context.Background(), config.ComponentInfo{
		ID: "daemon", Packages: []string{"daemon"}, Units: []string{"daemon.service"},
	})
	if err == nil || !strings.Contains(err.Error(), "daemon.service") {
		t.Fatalf("disable failure was hidden: %v", err)
	}
}

func TestRemoveStopsBeforePurgeWhenStockUnitCannotBeDisabled(t *testing.T) {
	runner := &disableFailureRunner{}
	s := New(runner, testLogger{})
	err := s.remove(context.Background(), config.ComponentInfo{
		ID: "daemon", Packages: []string{"daemon"}, Units: []string{"daemon.service"},
	})
	if err == nil || !strings.Contains(err.Error(), "daemon.service") {
		t.Fatalf("disable failure was hidden: %v", err)
	}
	if runner.aptCalled {
		t.Fatal("package was purged while its daemon could still be running")
	}
}

type activeUnitsRunner struct{ packageInstalled map[string]bool }

func (r activeUnitsRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "dpkg-query" && len(args) > 0 {
		if r.packageInstalled[args[len(args)-1]] {
			return "install ok installed", nil
		}
		return "", errors.New("not installed")
	}
	if name == "systemctl" && len(args) > 0 && args[0] == "list-units" {
		return "netos-dnsmasq.service loaded active running DNS\nnetos-l2tp-office.service loaded active running VPN\n", nil
	}
	return "", nil
}

type sharedPackageRunner struct {
	installed map[string]bool
	aptArgs   []string
}

func (r *sharedPackageRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	switch name {
	case "dpkg-query":
		if len(args) > 0 && r.installed[args[len(args)-1]] {
			return "install ok installed", nil
		}
		return "", errors.New("not installed")
	case "apt-get":
		r.aptArgs = append([]string(nil), args...)
		return "", nil
	case "systemctl":
		if len(args) > 0 && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return "disabled", errors.New("disabled")
		}
	}
	return "", nil
}

func (r *sharedPackageRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r activeUnitsRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type catalogSnapshotRunner struct{ commands []string }

func (r *catalogSnapshotRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	joined := strings.Join(args, " ")
	switch {
	case name == "dpkg-query":
		return "dns\tinstall ok installed\nvpn\tinstall ok installed\n", nil
	case strings.Contains(joined, "list-units"):
		return "dns.service loaded inactive dead DNS\nvpn.service loaded inactive dead VPN\n", nil
	case strings.Contains(joined, "list-unit-files"):
		return "dns.service disabled enabled\nvpn.service disabled enabled\n", nil
	default:
		return "", fmt.Errorf("unexpected per-item probe: %s %s", name, joined)
	}
}

func (r *catalogSnapshotRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestStatusSnapshotsWholeCatalogInThreeProcesses(t *testing.T) {
	originalCatalog := config.Catalog
	config.Catalog = []config.ComponentInfo{
		{ID: "dns", Packages: []string{"dns"}, Units: []string{"dns.service"}},
		{ID: "vpn", Packages: []string{"vpn"}, Units: []string{"vpn.service"}},
	}
	t.Cleanup(func() { config.Catalog = originalCatalog })
	runner := &catalogSnapshotRunner{}
	status := New(runner, testLogger{}).Status(context.Background())
	if !status["dns"] || !status["vpn"] {
		t.Fatalf("status=%v", status)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("status launched %d processes instead of 3: %v", len(runner.commands), runner.commands)
	}
}

func TestMetadataStatusRunningAndUnitPatterns(t *testing.T) {
	originalCatalog := config.Catalog
	config.Catalog = []config.ComponentInfo{
		{ID: "dns", Packages: []string{"dns"}, RunUnits: []string{"netos-dnsmasq.service"}},
		{ID: "vpn", Packages: []string{"vpn"}, RunUnits: []string{"netos-l2tp-*.service"}},
		{ID: "idle", Packages: []string{"idle"}, RunUnits: []string{"netos-idle.service"}},
		{ID: "library"},
	}
	t.Cleanup(func() { config.Catalog = originalCatalog })

	s := New(activeUnitsRunner{packageInstalled: map[string]bool{"dns": true}}, testLogger{})
	if s.Name() != "components" {
		t.Fatalf("Name=%q", s.Name())
	}
	if err := s.Health(context.Background(), &config.Config{}); err != nil {
		t.Fatal(err)
	}
	status := s.Status(context.Background())
	if !status["dns"] || status["vpn"] || status["idle"] {
		t.Fatalf("unexpected status: %#v", status)
	}
	if _, exists := status["library"]; exists {
		t.Fatalf("package-less component must not be in status: %#v", status)
	}
	running := s.Running(context.Background())
	if !running["dns"] || !running["vpn"] || running["idle"] {
		t.Fatalf("unexpected running state: %#v", running)
	}
	if anyUnitActive([]string{"[invalid"}, []string{"anything"}) {
		t.Fatal("invalid unit pattern unexpectedly matched")
	}
}

func TestPlanCoversCreateDeleteEssentialAndNoop(t *testing.T) {
	originalCatalog := config.Catalog
	config.Catalog = []config.ComponentInfo{
		{ID: "partial", Title: "Partial", Packages: []string{"one", "two"}},
		{ID: "remove", Title: "Remove", Packages: []string{"remove"}},
		{ID: "essential", Title: "Essential", Packages: []string{"essential"}, Essential: true},
		{ID: "absent", Title: "Absent", Packages: []string{"absent"}},
	}
	t.Cleanup(func() { config.Catalog = originalCatalog })
	s := New(packageStateRunner{"one": true, "remove": true, "essential": true}, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "partial", Installed: true}}}
	actions, err := s.Plan(&config.Config{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("actions=%#v", actions)
	}
	if actions[0].Kind != "create" || actions[0].Target != "Partial" {
		t.Fatalf("create action=%#v", actions[0])
	}
	if actions[1].Kind != "delete" || actions[1].Target != "Remove" || !actions[1].Disruptive {
		t.Fatalf("delete action=%#v", actions[1])
	}
}

func TestSharedPackageIsProtectedForEnabledComponent(t *testing.T) {
	originalCatalog := config.Catalog
	config.Catalog = []config.ComponentInfo{
		{ID: "l2tp", Title: "L2TP", Packages: []string{"xl2tpd", "ppp"}},
		{ID: "pppoe", Title: "PPPoE", Packages: []string{"pppoe", "ppp"}},
	}
	t.Cleanup(func() { config.Catalog = originalCatalog })
	desired := map[string]bool{"l2tp": true}
	protected := protectedComponentPackages(desired)
	if !protected["xl2tpd"] || !protected["ppp"] || protected["pppoe"] {
		t.Fatalf("protected packages=%v", protected)
	}

	// Once the PPPoE-only package is gone, the shared ppp package must not keep
	// producing a perpetual delete action for the disabled component.
	s := New(packageStateRunner{"xl2tpd": true, "ppp": true}, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "l2tp", Installed: true}}}
	actions, err := s.Plan(&config.Config{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("shared package caused a dirty plan: %#v", actions)
	}

	// If the exclusive PPPoE package is still present, only it is removable.
	runner := &removalFailureRunner{}
	s = New(runner, testLogger{})
	err = s.removeProtected(context.Background(), config.Catalog[1], protected)
	if err == nil {
		t.Fatal("expected fake purge failure")
	}
	if !containsArgument(runner.aptArgs, "pppoe") || containsArgument(runner.aptArgs, "ppp") {
		t.Fatalf("shared ppp package was not protected: %v", runner.aptArgs)
	}
}

func TestApplyRemovesOnlyExclusivePackageFromDisabledComponent(t *testing.T) {
	originalCatalog := config.Catalog
	config.Catalog = []config.ComponentInfo{
		{ID: "l2tp", Title: "L2TP", Packages: []string{"xl2tpd", "ppp"}},
		{ID: "pppoe", Title: "PPPoE", Packages: []string{"pppoe", "ppp"}},
	}
	t.Cleanup(func() { config.Catalog = originalCatalog })
	runner := &sharedPackageRunner{installed: map[string]bool{"xl2tpd": true, "ppp": true, "pppoe": true}}
	s := New(runner, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "l2tp", Installed: true}}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !containsArgument(runner.aptArgs, "pppoe") || containsArgument(runner.aptArgs, "ppp") || containsArgument(runner.aptArgs, "xl2tpd") {
		t.Fatalf("Apply purged a package required by L2TP: %v", runner.aptArgs)
	}
}

func TestDesiredComponentStateHandlesNilAndLastDuplicate(t *testing.T) {
	if got := desiredComponentState(nil); len(got) != 0 {
		t.Fatalf("nil config state=%v", got)
	}
	cfg := &config.Config{Components: []config.Component{
		{ID: "x", Installed: true}, {ID: "x", Installed: false},
	}}
	if desiredComponentState(cfg)["x"] {
		t.Fatal("last duplicate component state did not win")
	}
}

func TestExternalCurrentAndUnknownInstallerFailureBranches(t *testing.T) {
	target := filepath.Join(t.TempDir(), "tool")
	rel := externalRelease{Version: "v1.0.0", Target: target, VersionArgs: []string{"version"}}
	s := New(outputVersionRunner{output: "tool 1.0.0"}, testLogger{})
	if s.externalCurrent(context.Background(), rel) {
		t.Fatal("missing target reported current")
	}
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	withoutRunner := New(nil, testLogger{})
	if withoutRunner.externalCurrent(context.Background(), rel) {
		t.Fatal("target without runner reported current")
	}
	rel.VersionArgs = nil
	if s.externalCurrent(context.Background(), rel) {
		t.Fatal("target without version command reported current")
	}
	if err := s.installExternal(context.Background(), config.ComponentInfo{ID: "unknown", Title: "Unknown", External: true}); err == nil {
		t.Fatal("unknown external component installed without a release")
	}
	if any, all := s.componentState(context.Background(), config.ComponentInfo{ID: "unknown", External: true}); any || all {
		t.Fatalf("unknown external state: any=%v all=%v", any, all)
	}
	if err := s.install(context.Background(), config.ComponentInfo{ID: "metadata-only"}); err != nil {
		t.Fatal(err)
	}
	if err := s.removeProtected(context.Background(), config.ComponentInfo{ID: "absent", Packages: []string{"absent"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExternalCurrentTimesOutHungVersionCommand(t *testing.T) {
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	originalTimeout := externalVersionTimeout
	externalVersionTimeout = 10 * time.Millisecond
	t.Cleanup(func() { externalVersionTimeout = originalTimeout })
	s := New(blockingVersionRunner{}, testLogger{})
	started := time.Now()
	if s.externalCurrent(context.Background(), externalRelease{
		Version: "v1.0.0", Target: target, VersionArgs: []string{"version"},
	}) {
		t.Fatal("hung version command reported current")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("version command timeout took %s", elapsed)
	}
}

func TestRemoveExternalFileAndReportFilesystemError(t *testing.T) {
	original := externalReleases
	t.Cleanup(func() { externalReleases = original })

	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	externalReleases = map[string]externalRelease{"tool": {Target: target}}
	if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(outputVersionRunner{}, testLogger{})
	if err := s.remove(context.Background(), config.ComponentInfo{ID: "tool", External: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("external target remains: %v", err)
	}
	if _, err := os.Stat(target + ".netos-owned"); !os.IsNotExist(err) {
		t.Fatalf("external ownership marker remains: %v", err)
	}

	dirTarget := filepath.Join(t.TempDir(), "nonempty")
	if err := os.Mkdir(dirTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirTarget, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	externalReleases = map[string]externalRelease{"tool": {Target: dirTarget}}
	if err := os.WriteFile(externalOwnerPath(externalReleases["tool"]), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.remove(context.Background(), config.ComponentInfo{ID: "tool", External: true}); err == nil {
		t.Fatal("filesystem removal error was hidden")
	}
}
