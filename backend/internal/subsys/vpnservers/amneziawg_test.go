package vpnservers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// awgServerRunner answers AmneziaWG commands as their WireGuard counterparts
// and keeps the real command line for assertions.
type awgServerRunner struct {
	*fakeRunner
	real []string
}

func (r *awgServerRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.real = append(r.real, name+" "+strings.Join(args, " "))
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
	return r.fakeRunner.Run(ctx, name, translated...)
}

func (r *awgServerRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *awgServerRunner) count(prefix string) int {
	n := 0
	for _, c := range r.real {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func awgServerConfig() *config.Config {
	cfg := serverConfig()
	cfg.Components = []config.Component{{ID: "amneziawg", Installed: true}}
	cfg.VPNServers[0].Config["amneziawg"] = map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "s2": 25, "h1": "100-200", "h2": "300", "h3": "400", "h4": "500", "i1": "<b 0xc0ffee><t>"}
	return cfg
}

func newAWGServerSubsystem(t *testing.T) (*Subsystem, *awgServerRunner) {
	t.Helper()
	s, inner := newTestSubsystem(t)
	r := &awgServerRunner{fakeRunner: inner}
	s.Runner = r
	return s, r
}

func TestApplyCreatesAmneziaWGServer(t *testing.T) {
	s, r := newAWGServerSubsystem(t)
	cfg := awgServerConfig()
	if problems := cfg.Validate(); problems.HasErrors() {
		t.Fatal(problems.Problems)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link add name wg-srv1 type amneziawg") != 1 || r.count("awg syncconf wg-srv1") != 1 || r.count("wg ") != 0 {
		t.Fatalf("AmneziaWG server not built by its own module and tool:\n%s", strings.Join(r.real, "\n"))
	}
	conf, err := os.ReadFile(filepath.Join(s.StateDir, "wg-srv1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ListenPort = 51820\n", "Jc = 4\n", "H1 = 100-200\n", "I1 = <b 0xc0ffee><t>\n", "AllowedIPs = 10.9.0.2/32"} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("server config lacks %q:\n%s", want, conf)
		}
	}
	owned, _ := os.ReadFile(s.ownedPath())
	if !strings.Contains(string(owned), `"amneziawg"`) {
		t.Fatalf("link kind not recorded: %s", owned)
	}
}

func TestAmneziaWGServerObfuscationChangeRecreatesLink(t *testing.T) {
	s, r := newAWGServerSubsystem(t)
	cfg := awgServerConfig()
	for i := 0; i < 2; i++ {
		if err := s.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	if r.count("ip link delete wg-srv1") != 0 {
		t.Fatal("unchanged obfuscation dropped all client sessions")
	}
	delete(cfg.VPNServers[0].Config["amneziawg"].(map[string]any), "i1")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link delete wg-srv1") != 1 || r.count("ip link add name wg-srv1 type amneziawg") != 2 {
		t.Fatalf("removed signature not cleared from the kernel:\n%s", strings.Join(r.real, "\n"))
	}
}

func TestSwitchingServerToAmneziaWGReplacesLink(t *testing.T) {
	s, r := newAWGServerSubsystem(t)
	cfg := serverConfig()
	cfg.Components = append(cfg.Components, config.Component{ID: "amneziawg", Installed: true})
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.VPNServers[0].Config["amneziawg"] = map[string]any{"jc": 4, "jmin": 40, "jmax": 70}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if r.count("ip link add name wg-srv1 type wireguard") != 1 || r.count("ip link add name wg-srv1 type amneziawg") != 1 || r.count("ip link delete wg-srv1") == 0 {
		t.Fatalf("kind switch did not replace the link:\n%s", strings.Join(r.real, "\n"))
	}
}

func TestAmneziaWGServerNeedsItsOwnComponent(t *testing.T) {
	cfg := awgServerConfig()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	found := false
	for _, p := range cfg.Validate().Problems {
		found = found || strings.Contains(p.Message, "компонент «AmneziaWG»")
	}
	if !found {
		t.Fatal("AmneziaWG server accepted without its component")
	}
	cfg = awgServerConfig()
	cfg.VPNServers[0].Config["amneziawg"] = map[string]any{"jmin": 80, "jmax": 70}
	found = false
	for _, p := range cfg.Validate().Problems {
		found = found || strings.Contains(p.Message, "Jmin не может быть больше Jmax")
	}
	if !found {
		t.Fatal("invalid server obfuscation accepted")
	}
}
