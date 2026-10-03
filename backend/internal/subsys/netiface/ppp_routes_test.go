package netiface

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPPPMetricChangeRemovesOnlyFormerOwnedDefault(t *testing.T) {
	ctx := context.Background()
	var commands []string
	live := map[string]bool{"100": true, "110": true, "120": true}
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if strings.HasPrefix(command, "ip -4 route del default dev ppp-qa-metric metric ") {
			delete(live, args[len(args)-1])
			return "", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	cfg := config.Default()
	cfg.WANs = []config.WAN{{ID: "qa-metric", Enabled: true, Proto: "l2tp", Metric: 100}}
	wanted, err := s.preparePPPDefaultRouteOwnership(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.syncPPPDefaultRouteOwnership(ctx, wanted); err != nil {
		t.Fatal(err)
	}
	for _, metric := range []int{110, 120} {
		cfg.WANs[0].Metric = metric
		wanted, err = s.preparePPPDefaultRouteOwnership(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.syncPPPDefaultRouteOwnership(ctx, wanted); err != nil {
			t.Fatal(err)
		}
	}
	if live["100"] || live["110"] || !live["120"] {
		t.Fatalf("former PPP defaults remained: %#v; commands: %v", live, commands)
	}
	for _, command := range commands {
		if strings.Contains(command, "dev ppp-other") {
			t.Fatalf("foreign PPP route was modified: %s", command)
		}
	}
	owned, err := s.readPPPDefaultRoutes()
	if err != nil || len(owned) != 1 || owned[0].Metric != 120 {
		t.Fatalf("ownership after metric changes: %#v, %v", owned, err)
	}
}

func TestPPPMetricCleanupFailureRetainsOwnershipForRetry(t *testing.T) {
	ctx := context.Background()
	fail := true
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if command == "ip -4 route del default dev ppp-qa-retry metric 100" && fail {
			return "", errors.New("route busy")
		}
		if command == "ip -4 route show default" {
			return "default dev ppp-qa-retry metric 100\ndefault dev ppp-qa-retry metric 110\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	if err := s.writePPPDefaultRoutes([]pppDefaultRoute{{Interface: "ppp-qa-retry", Metric: 100}, {Interface: "ppp-qa-retry", Metric: 110}}); err != nil {
		t.Fatal(err)
	}
	wanted := []pppDefaultRoute{{Interface: "ppp-qa-retry", Metric: 110}}
	if err := s.syncPPPDefaultRouteOwnership(ctx, wanted); err == nil {
		t.Fatal("live old default was accepted after failed deletion")
	}
	owned, err := s.readPPPDefaultRoutes()
	if err != nil || len(owned) != 2 {
		t.Fatalf("retry lost old ownership: %#v, %v", owned, err)
	}
	fail = false
	if err := s.syncPPPDefaultRouteOwnership(ctx, wanted); err != nil {
		t.Fatal(err)
	}
	owned, err = s.readPPPDefaultRoutes()
	if err != nil || len(owned) != 1 || owned[0].Metric != 110 {
		t.Fatalf("retry did not settle ownership: %#v, %v", owned, err)
	}
}

func TestRecoverPPPMetricRequiresNetOSOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ppp-options")
	if err := os.WriteFile(path, []byte("defaultroute-metric 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if metric, err := recoverPPPMetric(path); err != nil || metric != 0 {
		t.Fatalf("foreign options claimed: %d, %v", metric, err)
	}
	if err := os.WriteFile(path, []byte("# Сгенерировано netOS.\ndefaultroute-metric 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if metric, err := recoverPPPMetric(path); err != nil || metric != 100 {
		t.Fatalf("owned metric lost: %d, %v", metric, err)
	}
}

func TestPPPRouteCleanupAfterInterfaceDisappears(t *testing.T) {
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ip -4 route del default dev ppp-qa-gone metric 120":
			return "", errors.New("Cannot find device ppp-qa-gone")
		case "ip -4 route show default":
			return "default via 192.0.2.1 dev eth0 metric 50\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	if err := s.writePPPDefaultRoutes([]pppDefaultRoute{{Interface: "ppp-qa-gone", Metric: 120}}); err != nil {
		t.Fatal(err)
	}
	if err := s.syncPPPDefaultRouteOwnership(context.Background(), nil); err != nil {
		t.Fatalf("disappeared PPP interface should leave no stale route: %v", err)
	}
	owned, err := s.readPPPDefaultRoutes()
	if err != nil || len(owned) != 0 {
		t.Fatalf("stale ownership remained: %#v, %v", owned, err)
	}
}

func TestMissingPPPDefaultIsRestoredWithoutReplacingOtherWAN(t *testing.T) {
	routes := "default via 198.18.1.1 dev eth2 metric 200\n"
	adds := 0
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ip -4 route show default":
			return routes, nil
		case "ip -4 route add default dev ppp-wan1 metric 100":
			adds++
			routes += "default dev ppp-wan1 metric 100\n"
			return "", nil
		}
		return "", errors.New("unexpected command: " + command)
	})
	s := NewWAN(runner)
	route := pppDefaultRoute{Interface: "ppp-wan1", Metric: 100}
	for range 2 {
		if err := s.ensurePPPDefaultRoute(context.Background(), route); err != nil {
			t.Fatal(err)
		}
	}
	if adds != 1 || !strings.Contains(routes, "dev eth2 metric 200") {
		t.Fatalf("PPP recovery changed other WAN or was not idempotent: adds=%d routes=%q", adds, routes)
	}
}
