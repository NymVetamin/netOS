package apply

import (
	"context"
	"github.com/netos-router/netos/internal/config"
	"testing"
)

func TestEngineAppliesEffectiveInterfacesAndRetainsDesired(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "p", Name: "eth0", Type: "physical", Enabled: false}}
	c.WANs = []config.WAN{{ID: "w", Interface: "p", Enabled: true}}
	calls := 0
	e := newTestEngine(t, &testSubsystem{apply: func(_ context.Context, r *config.Config) error {
		calls++
		if r.WANs[0].Enabled {
			t.Fatal("WAN overrides disabled port")
		}
		return nil
	}})
	if err := e.run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := e.RecoverStartupConnectivity(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !c.WANs[0].Enabled {
		t.Fatal("desired state changed or recovery omitted")
	}
}
