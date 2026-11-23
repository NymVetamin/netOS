package vpnservers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestWireGuardPeerKeySet(t *testing.T) {
	server := config.VPNServer{Peers: []config.VPNPeer{
		{Enabled: true, Credentials: map[string]string{"public_key": "first"}},
		{Enabled: false, Credentials: map[string]string{"public_key": "disabled"}},
		{Enabled: true, Credentials: map[string]string{"public_key": "second"}},
	}}
	for _, tc := range []struct {
		output string
		want   bool
	}{
		{"first\nsecond\n", true}, {" second\tfirst \n", true}, {"", false},
		{"first\n", false}, {"first\nsecond\ndisabled", false}, {"first\nfirst\nsecond", false},
	} {
		if got := wireGuardPeerKeysMatch(server, tc.output); got != tc.want {
			t.Errorf("%q: %v", tc.output, got)
		}
	}
	server.Peers[0].Enabled = false
	server.Peers[2].Enabled = false
	if !wireGuardPeerKeysMatch(server, "") || wireGuardPeerKeysMatch(server, "first") {
		t.Fatal("disabled-only server must have no live peers")
	}
	server.Peers = nil
	if !wireGuardPeerKeysMatch(server, "") {
		t.Fatal("empty server")
	}
}

type peerQueryFailureRunner struct {
	*fakeRunner
	fail bool
}

func (r *peerQueryFailureRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.fail && name == "wg" && strings.Join(args, " ") == "show wg-srv1 peers" {
		return "", errors.New("peer query failed")
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestWireGuardPeerQueryFailureAndRetry(t *testing.T) {
	s, inner := newTestSubsystem(t)
	r := &peerQueryFailureRunner{fakeRunner: inner}
	s.Runner = r
	ctx := context.Background()
	cfg := serverConfig()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r.fail = true
	for range 2 {
		if err := s.Health(ctx, cfg); err == nil || !strings.Contains(err.Error(), "peer query failed") {
			t.Fatalf("query failure: %v", err)
		}
		if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 1 {
			t.Fatalf("query failure plan: %+v %v", actions, err)
		}
	}
	r.fail = false
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
		t.Fatalf("recovered query: %+v %v", actions, err)
	}
}

func TestWireGuardPeerDriftPlansRepair(t *testing.T) {
	for _, awg := range []bool{false, true} {
		for _, drift := range []string{"missing", "extra"} {
			t.Run(strings.Join([]string{map[bool]string{false: "wg", true: "awg"}[awg], drift}, "/"), func(t *testing.T) {
				s, r := newTestSubsystem(t)
				cfg := serverConfig()
				if awg {
					cfg = awgServerConfig()
					s.Runner = &awgServerRunner{fakeRunner: r}
				}
				ctx := context.Background()
				if err := s.Apply(ctx, cfg); err != nil {
					t.Fatal(err)
				}
				if drift == "missing" {
					r.peers = ""
				} else {
					r.peers += "unexpected-peer\n"
				}
				if err := s.Health(ctx, cfg); err == nil {
					t.Error("live peer drift passed Health")
				}
				if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 1 || !actions[0].Disruptive {
					t.Errorf("drift plan: %+v %v", actions, err)
				}
				for range 2 {
					r.commands = nil
					if err := s.Apply(ctx, cfg); err != nil {
						t.Fatal(err)
					}
					if err := s.Health(ctx, cfg); err != nil {
						t.Fatal(err)
					}
					if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
						t.Fatalf("repaired plan: %+v %v", actions, err)
					}
					for _, cmd := range r.commands {
						if strings.Contains(cmd, "ip link add") || strings.Contains(cmd, "ip link delete") {
							t.Fatalf("peer repair recreated interface: %s", cmd)
						}
					}
				}
			})
		}
	}
}

func BenchmarkWireGuardPeerHealth(b *testing.B) {
	for _, count := range []int{8, 512} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			root := b.TempDir()
			s := New(nil, filepath.Join(root, "state"))
			s.SysClassNet = filepath.Join(root, "net")
			s.ProcSysNet = filepath.Join(root, "proc")
			s.AppArmorDir = filepath.Join(root, "apparmor")
			s.AppArmorProfiles = filepath.Join(root, "profiles")
			r := &fakeRunner{s: s}
			s.Runner = r
			cfg := serverConfig()
			cfg.VPNServers[0].Peers = nil
			for i := 0; i < count; i++ {
				var key [32]byte
				binary.LittleEndian.PutUint32(key[:], uint32(i+1))
				cfg.VPNServers[0].Peers = append(cfg.VPNServers[0].Peers, config.VPNPeer{Enabled: true, Address: fmt.Sprintf("10.9.%d.%d", i/254, i%254+1), Credentials: map[string]string{"public_key": base64.StdEncoding.EncodeToString(key[:])}})
			}
			ctx := context.Background()
			if err := s.Apply(ctx, cfg); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				r.commands = r.commands[:0]
				if err := s.Health(ctx, cfg); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(r.commands)), "commands/op")
		})
	}
}
