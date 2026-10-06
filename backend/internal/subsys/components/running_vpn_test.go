package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type vpnRuntimeRunner struct {
	links string
	err   error
	units string
}

func (r vpnRuntimeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "ip" {
		return r.links, r.err
	}
	if name == "systemctl" && len(args) > 0 && args[0] == "list-units" {
		return r.units, nil
	}
	return "", nil
}

func (r vpnRuntimeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestRunningWireGuardRequiresLiveOwnedInterface(t *testing.T) {
	for _, tc := range []struct {
		name, ownership, links string
		err                    error
		want                   bool
	}{
		{"server", `[{"name":"wg-srv22","type":"wireguard"}]`, `[{"ifname":"wg-srv22","flags":["UP","LOWER_UP"]}]`, nil, true},
		{"channel", `[{"name":"wg-ch4","type":"wireguard"}]`, `[{"ifname":"wg-ch4","flags":["UP"]}]`, nil, true},
		{"foreign", `[]`, `[{"ifname":"wg-srv22","flags":["UP"]}]`, nil, false},
		{"different-owner", `[{"name":"wg-ch4","type":"wireguard"}]`, `[{"ifname":"wg-srv22","flags":["UP"]}]`, nil, false},
		{"down", `[{"name":"wg-ch4","type":"wireguard"}]`, `[{"ifname":"wg-ch4","flags":[]}]`, nil, false},
		{"removed", `[{"name":"wg-ch4","type":"wireguard"}]`, `[]`, nil, false},
		{"other-type", `[{"name":"wg-ch4","type":"ikev2"}]`, `[{"ifname":"wg-ch4","flags":["UP"]}]`, nil, false},
		{"bad-owner", `invalid`, `[{"ifname":"wg-ch4","flags":["UP"]}]`, nil, false},
		{"bad-links", `[{"name":"wg-ch4","type":"wireguard"}]`, `invalid`, nil, false},
		{"probe-failed", `[{"name":"wg-ch4","type":"wireguard"}]`, ``, errors.New("ip failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(vpnRuntimeRunner{links: tc.links, err: tc.err}, testLogger{})
			s.StateDir = t.TempDir()
			filename := "owned-vpn-servers.json"
			if tc.name == "channel" {
				filename = "owned-channels.json"
			}
			if err := os.WriteFile(filepath.Join(s.StateDir, filename), []byte(tc.ownership), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := s.Running(context.Background())["wireguard"]; got != tc.want {
				t.Fatalf("running=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunningL2TPIncludesWANChannelsAndServers(t *testing.T) {
	for _, unit := range []string{"netos-l2tp-wan1.service", "netos-vpn-l2tp-ch31.service", "netos-vpn-l2tp-srv30.service"} {
		s := New(vpnRuntimeRunner{units: unit + " loaded active running L2TP\n"}, testLogger{})
		s.StateDir = t.TempDir()
		if !s.Running(context.Background())["l2tp"] {
			t.Fatalf("active %s is not counted", unit)
		}
	}
	s := New(vpnRuntimeRunner{units: "xl2tpd.service loaded active running foreign\n"}, testLogger{})
	if s.Running(context.Background())["l2tp"] {
		t.Fatal("stock daemon counted as netOS use")
	}
	for _, info := range config.Catalog {
		if info.ID == "l2tp" && !strings.Contains(strings.Join(info.Units, ","), "xl2tpd.service") {
			t.Fatal("stock daemon suppression lost")
		}
	}
}
