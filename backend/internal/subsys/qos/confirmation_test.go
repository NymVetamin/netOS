package qos

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func TestManagementMACRequiresKnownLANNeighbour(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	ctx := apply.WithManagementConnection(context.Background(), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
	for _, tc := range []struct {
		out  string
		good bool
	}{
		{`[{"dst":"192.0.2.2","lladdr":"02:00:00:00:00:99","state":["STALE"]}]`, true},
		{`[{"dst":"192.0.2.2","dev":"other","lladdr":"02:00:00:00:00:99","state":["REACHABLE"]}]`, false},
		{`[{"dst":"192.0.2.2","lladdr":"02:00:00:00:00:99","state":["FAILED"]}]`, false},
		{`[{"dst":"192.0.2.3","lladdr":"02:00:00:00:00:99","state":["REACHABLE"]}]`, false},
		{`[]`, false}, {`not json`, false},
	} {
		s := New(&fakeRunner{outputs: map[string]string{"ip -4 -j neigh show to 192.0.2.2 dev lan0": tc.out}}, t.TempDir())
		if got := s.managementMAC(ctx, cfg) != ""; got != tc.good {
			t.Fatalf("known=%v want %v for %s", got, tc.good, tc.out)
		}
		if s.managementMAC(context.Background(), cfg) != "" {
			t.Fatal("missing socket accepted")
		}
	}
}
