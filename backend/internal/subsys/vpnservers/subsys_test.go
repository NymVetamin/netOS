package vpnservers

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	s        *Subsystem
	commands []string
	address  string
	port     string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	switch {
	case cmd == "ip link add name wg-srv1 type wireguard":
		_ = os.MkdirAll(filepath.Join(r.s.SysClassNet, "wg-srv1"), 0o755)
		path := filepath.Join(r.s.ProcSysNet, "ipv6", "conf", "wg-srv1")
		_ = os.MkdirAll(path, 0o755)
		_ = os.WriteFile(filepath.Join(path, "disable_ipv6"), []byte("0"), 0o644)
	case cmd == "ip link delete wg-srv1":
		_ = os.RemoveAll(filepath.Join(r.s.SysClassNet, "wg-srv1"))
	case cmd == "wg show wg-srv1":
		if !r.s.linkExists("wg-srv1") {
			return "", errors.New("missing")
		}
	case cmd == "wg syncconf wg-srv1 "+filepath.Join(r.s.StateDir, "wg-srv1.conf"):
		r.port = "51820"
	case cmd == "wg show wg-srv1 listen-port":
		return r.port + "\n", nil
	case cmd == "ip -o -4 addr show dev wg-srv1":
		return r.address, nil
	case cmd == "ip -4 addr add 10.9.0.1/24 dev wg-srv1":
		r.address = "8: wg-srv1 inet 10.9.0.1/24 scope global wg-srv1\n"
	}
	return "", nil
}

func (r *fakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func serverConfig() *config.Config {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	cfg.VPNServers = []config.VPNServer{{
		ID: "home", Index: 1, Name: "Домашний VPN", Enabled: true, Type: "wireguard",
		Subnet: "10.9.0.1/24", Port: 51820, DefaultChannel: "direct",
		Config: map[string]any{"private_key": key, "mtu": 1380},
		Peers:  []config.VPNPeer{{ID: "phone", Name: "Телефон", Enabled: true, Address: "10.9.0.2", Credentials: map[string]string{"public_key": key}}},
	}}
	return cfg
}

func newTestSubsystem(t *testing.T) (*Subsystem, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	s := New(nil, filepath.Join(root, "state"))
	s.SysClassNet = filepath.Join(root, "sys", "class", "net")
	s.ProcSysNet = filepath.Join(root, "proc", "sys", "net")
	r := &fakeRunner{s: s}
	s.Runner = r
	return s, r
}

func TestRenderWireGuardServer(t *testing.T) {
	out, err := RenderWireGuard(serverConfig().VPNServers[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ListenPort = 51820", "AllowedIPs = 10.9.0.2/32", "# Телефон"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в:\n%s", want, out)
		}
	}
}

func TestApplyHealthAndCleanup(t *testing.T) {
	s, runner := newTestSubsystem(t)
	cfg := serverConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.StateDir, "wg-srv1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("права конфигурации: %o", info.Mode().Perm())
	}
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if s.linkExists("wg-srv1") {
		t.Fatal("интерфейс не удалён")
	}
	if _, err := os.Stat(filepath.Join(s.StateDir, "wg-srv1.conf")); !os.IsNotExist(err) {
		t.Fatal("секретный конфиг не удалён")
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{"wg syncconf wg-srv1", "ip link set dev wg-srv1 mtu 1380 up", "ip link delete wg-srv1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет команды %q:\n%s", want, joined)
		}
	}
}
