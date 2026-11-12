package channels

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// awgRunner reuses the WireGuard fake: the kernel side of AmneziaWG differs
// only in the link type and the tool name. It records the real commands.
type awgRunner struct {
	*channelRunner
	real []string
}

func (r *awgRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.real = append(r.real, command)
	// The fake models one kind at a time: AmneziaWG commands are answered as
	// their WireGuard counterparts.
	if name == "awg" {
		name = "wg"
	}
	translated := make([]string, len(args))
	for i, a := range args {
		if a == "amneziawg" {
			a = "wireguard"
		}
		translated[i] = a
	}
	if name == "ip" && strings.Join(args, " ") == "-d -o link show dev wg-ch1" {
		if !r.s.linkExists("wg-ch1") {
			return "", os.ErrNotExist
		}
		return "7: wg-ch1: <POINTOPOINT,UP> mtu 1420 \\    amneziawg \n", nil
	}
	return r.channelRunner.Run(ctx, name, translated...)
}

func (r *awgRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *awgRunner) count(prefix string) int {
	n := 0
	for _, c := range r.real {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func awgParams() map[string]any {
	return map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "s2": 25, "h1": "100-200", "h2": "300", "h3": "400", "h4": "500-600", "i1": "<b 0xc0ffee><r 8><t>"}
}

func awgChannelConfig() *config.Config {
	cfg := channelConfig()
	cfg.Components = []config.Component{{ID: "amneziawg", Installed: true}}
	cfg.Channels[len(cfg.Channels)-1].Config["amneziawg"] = awgParams()
	return cfg
}

func newAWGSubsystem(t *testing.T) (*Subsystem, *awgRunner) {
	t.Helper()
	s, inner := newTestSubsystem(t)
	r := &awgRunner{channelRunner: inner}
	s.Runner = r
	return s, r
}

func TestApplyCreatesAmneziaWGChannel(t *testing.T) {
	s, r := newAWGSubsystem(t)
	cfg := awgChannelConfig()
	if errs := cfg.Validate(); errs.HasErrors() {
		t.Fatal(errs)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link add name wg-ch1 type amneziawg") != 1 || r.count("awg syncconf wg-ch1") != 1 {
		t.Fatalf("AmneziaWG link not created by its own module and tool:\n%s", strings.Join(r.real, "\n"))
	}
	if r.count("wg ") != 0 || r.count("ip link add name wg-ch1 type wireguard") != 0 {
		t.Fatalf("WireGuard tooling used for an AmneziaWG channel:\n%s", strings.Join(r.real, "\n"))
	}
	synced := string(r.wgConfig)
	for _, want := range []string{"Jc = 4\n", "Jmin = 40\n", "S2 = 25\n", "H1 = 100-200\n", "H4 = 500-600\n", "I1 = <b 0xc0ffee><r 8><t>\n", "ListenPort = 51820\n"} {
		if !strings.Contains(synced, want) {
			t.Fatalf("synced config lacks %q:\n%s", want, synced)
		}
	}
	owned, err := os.ReadFile(filepath.Join(s.StateDir, "owned-channels.json"))
	if err != nil || !strings.Contains(string(owned), `"type": "amneziawg"`) {
		t.Fatalf("link kind not recorded for rollback: %s %v", owned, err)
	}
}

func TestAmneziaWGChangedObfuscationRecreatesLinkOnly(t *testing.T) {
	s, r := newAWGSubsystem(t)
	cfg := awgChannelConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link delete wg-ch1") != 0 {
		t.Fatal("unchanged obfuscation dropped the tunnel")
	}
	// The kernel keeps a signature that is merely absent from the file.
	delete(cfg.Channels[len(cfg.Channels)-1].Config["amneziawg"].(map[string]any), "i1")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link delete wg-ch1") != 1 || r.count("ip link add name wg-ch1 type amneziawg") != 2 {
		t.Fatalf("removed signature was not cleared from the kernel:\n%s", strings.Join(r.real, "\n"))
	}
	if strings.Contains(string(r.wgConfig), "I1 =") {
		t.Fatal("removed signature still synced")
	}
}

func TestSwitchingWireGuardToAmneziaWGReplacesLink(t *testing.T) {
	s, r := newAWGSubsystem(t)
	cfg := channelConfig()
	cfg.Components = append(cfg.Components, config.Component{ID: "amneziawg", Installed: true})
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Channels[len(cfg.Channels)-1].Config["amneziawg"] = awgParams()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link add name wg-ch1 type wireguard") != 1 || r.count("ip link add name wg-ch1 type amneziawg") != 1 || r.count("ip link delete wg-ch1") == 0 {
		t.Fatalf("kind switch did not replace the link:\n%s", strings.Join(r.real, "\n"))
	}
}

func TestRenderWireGuardKeepsPlainChannelsUnchanged(t *testing.T) {
	plain, err := RenderWireGuard(channelConfig().Channels[len(channelConfig().Channels)-1])
	if err != nil {
		t.Fatal(err)
	}
	if amneziaLines(plain) != "" {
		t.Fatalf("plain WireGuard config gained obfuscation:\n%s", plain)
	}
}
