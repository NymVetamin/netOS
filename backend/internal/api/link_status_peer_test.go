package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
)

type peerStatusRunner struct {
	output string
	fail   bool
	tool   string
	calls  int
}

func (r *peerStatusRunner) Run(_ context.Context, tool string, args ...string) (string, error) {
	r.calls++
	if r.fail || tool != r.tool {
		return "", fmt.Errorf("command failed")
	}
	return r.output, nil
}
func (r *peerStatusRunner) RunInput(ctx context.Context, _ string, tool string, args ...string) (string, error) {
	return r.Run(ctx, tool, args...)
}

func TestSharedWireGuardStatusSelectsExitPeer(t *testing.T) {
	for _, tool := range []string{"wg", "awg"} {
		t.Run(tool, func(t *testing.T) {
			cfg := &config.Config{VPNServers: []config.VPNServer{{ID: "server", Index: 7, Type: "wireguard", Enabled: true, Config: map[string]any{}, Peers: []config.VPNPeer{
				{ID: "A", Enabled: true, UseAsChannel: true, Credentials: map[string]string{"public_key": "keyA"}},
				{ID: "B", Enabled: true, Credentials: map[string]string{"public_key": "keyB"}},
			}}}}
			if tool == "awg" {
				cfg.VPNServers[0].Config["amneziawg"] = map[string]any{}
			}
			cfg.Normalize()
			r := &peerStatusRunner{tool: tool}
			s := &Server{Collector: &runtime.Collector{Runner: r}}
			stats := []runtime.InterfaceStat{{Name: "wg-srv7", Up: true}}
			check := func(want bool) {
				t.Helper()
				_, rows := s.liveLinks(context.Background(), cfg, stats)
				if len(rows) != 1 || rows[0]["up"] != want {
					t.Fatalf("status=%v want=%v", rows, want)
				}
			}
			now := time.Now().Unix()
			for _, stamp := range []string{"0", fmt.Sprint(now - 600), "bad", "-1"} {
				r.output = fmt.Sprintf("keyB\t%d\nkeyA\t%s\n", now, stamp)
				check(false)
				check(false)
			}
			r.output = fmt.Sprintf("keyB\t%d\n", now)
			check(false)
			r.output += fmt.Sprintf("keyA\t%d\n", now)
			check(true)
			r.fail = true
			check(false)
			r.fail = false
			check(true)
			s.ChannelHealth = downProbe(true)
			check(false)
			s.ChannelHealth = nil
			check(true)
			cfg.VPNServers[0].Peers[0].Credentials["public_key"] = "rotated"
			check(false)
			r.output = fmt.Sprintf("rotated\t%d\n", now)
			check(true)
			cfg.VPNServers[0].Peers[0].UseAsChannel = false
			cfg.VPNServers[0].Peers[1].UseAsChannel = true
			cfg.Normalize()
			check(false)
			r.output = fmt.Sprintf("keyB\t%d\n", now)
			check(true)
			cfg.VPNServers[0].Peers[1].Enabled = false
			check(false)
			cfg.VPNServers[0].Peers[1].Enabled = true
			check(true)
			cfg.VPNServers[0].Enabled = false
			check(false)
			cfg.VPNServers[0].Enabled = true
			check(true)
			stats[0].Up = false
			before := r.calls
			check(false)
			if r.calls != before {
				t.Fatal("queried down interface")
			}
			stats[0].Up = true
			cfg.VPNServers[0].Peers = nil
			check(false)
			cfg.VPNServers = nil
			check(false)
		})
	}
}
