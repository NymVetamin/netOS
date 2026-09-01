package components

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type testLogger struct{}

func (testLogger) Infof(string, ...any)  {}
func (testLogger) Warnf(string, ...any)  {}
func (testLogger) Errorf(string, ...any) {}

type removalFailureRunner struct{ aptArgs []string }

func (r *removalFailureRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "dpkg-query" {
		return "install ok installed", nil
	}
	if name == "apt-get" {
		r.aptArgs = append([]string(nil), args...)
		return "", errors.New("purge failed")
	}
	return "", nil
}
func (r *removalFailureRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type componentRunner struct{ calls int }

func (r *componentRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", nil
}

func (r *componentRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

type packageStateRunner map[string]bool

func (r packageStateRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "dpkg-query" && len(args) > 0 && r[args[len(args)-1]] {
		return "install ok installed", nil
	}
	return "", errors.New("not installed")
}

func (r packageStateRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestComponentStateDistinguishesPartialInstallation(t *testing.T) {
	s := New(packageStateRunner{"first": true}, testLogger{})
	anyInstalled, allInstalled := s.componentState(context.Background(), config.ComponentInfo{
		ID: "partial", Packages: []string{"first", "second"},
	})
	if !anyInstalled || allInstalled {
		t.Fatalf("partial state lost: any=%v all=%v", anyInstalled, allInstalled)
	}
}

func TestRemoveDoesNotPurgeEssentialPackage(t *testing.T) {
	runner := &componentRunner{}
	s := New(runner, nil)
	err := s.remove(context.Background(), config.ComponentInfo{
		ID: "qos", Packages: []string{"iproute2"}, Essential: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("для базового пакета выполнено %d внешних команд", runner.calls)
	}
}

func TestApplyReportsRemovalFailure(t *testing.T) {
	// Apply reconciles every catalog entry, not only the component mentioned by
	// this test.  Point external releases at the test directory so a root test
	// run on an installed router can never remove the live Xray or dnsproxy
	// binaries while exercising an unrelated apt failure.
	originalReleases := externalReleases
	isolatedReleases := make(map[string]externalRelease, len(originalReleases))
	for id, rel := range originalReleases {
		rel.Target = filepath.Join(t.TempDir(), id)
		isolatedReleases[id] = rel
	}
	externalReleases = isolatedReleases
	t.Cleanup(func() { externalReleases = originalReleases })

	runner := &removalFailureRunner{}
	s := New(runner, testLogger{})
	cfg := &config.Config{Components: []config.Component{{ID: "dnsmasq", Installed: false}}}
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "удалить dnsmasq") {
		t.Fatalf("ошибка удаления потеряна: %v", err)
	}
	if !containsArgument(runner.aptArgs, "--autoremove") {
		t.Fatalf("dependencies would remain after purge: %v", runner.aptArgs)
	}
}

func containsArgument(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}

// Компонент, у которого пакет тянет за собой запускаемую службу, обязан
// перечислять её юнит: иначе после установки демон поднимется со своим
// конфигом и займёт порт, на котором должен работать netOS.
func TestComponentsWithDaemonsDeclareTheirUnits(t *testing.T) {
	needUnits := map[string]string{
		"dnsmasq":         "dnsmasq.service",
		"unbound":         "unbound.service",
		"l2tp":            "xl2tpd.service",
		"isc-dhcp-server": "isc-dhcp-server.service",
	}
	for id, unit := range needUnits {
		info, ok := config.ComponentByID(id)
		if !ok {
			t.Fatalf("компонент %s исчез из каталога", id)
		}
		var found bool
		for _, u := range info.Units {
			if u == unit {
				found = true
			}
		}
		if !found {
			t.Errorf("компонент %s не гасит штатный юнит %s: он займёт порт после установки", id, unit)
		}
	}
}
