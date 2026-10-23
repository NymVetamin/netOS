package routing

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestUnchangedStaticRouteDoesNotReplace(t *testing.T) {
	r := &recordingRunner{responses: map[string]runnerResponse{"ip -4 route show table all proto static": {out: "192.0.2.0/24 dev eth0 proto static scope link metric 5\n"}}}
	cfg := routeConfig(config.StaticRoute{Enabled: true, Destination: "192.0.2.0/24", Interface: "eth0", Metric: 5})
	if err := New(r).applyRoutes(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(commandStrings(r.commands), "route replace") {
		t.Fatal("unchanged route replaced")
	}
}

func TestStaticRouteDifferencesKeepRepair(t *testing.T) {
	if !staticRouteAlreadyApplied("unreachable 2001:db8:77::/48 dev lo table 200 metric 9 pref medium", config.StaticRoute{Destination: "2001:db8:77::/48", Type: "unreachable", Table: "200", Metric: 9}) {
		t.Fatal("kernel synthetic device prevented match")
	}
	route := config.StaticRoute{Destination: "192.0.2.0/24", Interface: "eth0", Metric: 5}
	for _, line := range []string{
		"192.0.2.0/24 dev eth0 proto 202 metric 5",
		"192.0.2.0/24 dev eth0 proto static metric 6",
		"192.0.2.0/24 dev eth1 proto static metric 5",
		"192.0.2.0/24 dev eth0 proto static metric 5 mtu 1200",
		"192.0.2.0/24 dev eth0 proto static metric 5 src 192.0.2.2",
		"192.0.2.0/24 dev eth0 proto static metric 5 onlink",
		"192.0.2.0/24 dev eth0 proto static metric 5 scope host",
		"192.0.2.0/24 dev eth0 proto static metric 5 pref high",
	} {
		if staticRouteAlreadyApplied(line, route) {
			t.Fatalf("drift ignored: %s", line)
		}
	}
}
