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

func (r handshakeRunner) Run(context.Context, string, ...string) (string, error) {
	return fmt.Sprintf("peer\t%d\n", r.timestamp), nil
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
