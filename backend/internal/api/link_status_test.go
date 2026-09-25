package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
)

type handshakeRunner struct{ timestamp int64 }

type downProbe bool

func (d downProbe) ProbeDown(string) bool { return bool(d) }

func (r handshakeRunner) Run(context.Context, string, ...string) (string, error) {
	return fmt.Sprintf("peer\t%d\n", r.timestamp), nil
}

func TestStatusReflectsProbeFailures(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "wanport", Name: "eth9"})
	cfg.WANs = append(cfg.WANs, config.WAN{ID: "wan", Name: "WAN", Interface: "wanport", Enabled: true})
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "wg", Index: 1, Name: "WG", Type: "wireguard", Enabled: true})
	stats := []runtime.InterfaceStat{{Name: "eth9", Up: true}, {Name: "wg-ch1", Up: true}}
	s := &Server{Collector: &runtime.Collector{Runner: handshakeRunner{timestamp: time.Now().Unix()}}, WANHealth: downProbe(true), ChannelHealth: downProbe(true)}
	wans, tunnels := s.liveLinks(context.Background(), cfg, stats)
	if wans[0]["up"] != false || wans[0]["probe_down"] != true || tunnels[0]["up"] != false || tunnels[0]["probe_down"] != true {
		t.Fatalf("probe failure hidden: wans=%v tunnels=%v", wans, tunnels)
	}
}
func (r handshakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestStatusRequiresRecentWireGuardHandshake(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "wg", Index: 1, Name: "WG", Type: "wireguard", Enabled: true})
	stats := []runtime.InterfaceStat{{Name: "wg-ch1", Up: true}}
	server := &Server{Collector: &runtime.Collector{Runner: handshakeRunner{timestamp: time.Now().Unix()}}}
	_, channels := server.liveLinks(context.Background(), cfg, stats)
	if len(channels) != 1 || channels[0]["up"] != true {
		t.Fatalf("fresh tunnel reported down: %v", channels)
	}
	server.Collector.Runner = handshakeRunner{timestamp: time.Now().Add(-10 * time.Minute).Unix()}
	_, channels = server.liveLinks(context.Background(), cfg, stats)
	if channels[0]["up"] != false {
		t.Fatalf("stale tunnel reported up: %v", channels)
	}
}
