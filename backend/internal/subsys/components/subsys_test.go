package components

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type componentRunner struct{ calls int }

func (r *componentRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", nil
}

func (r *componentRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
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
