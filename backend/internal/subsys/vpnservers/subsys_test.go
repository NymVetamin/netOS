package vpnservers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	s        *Subsystem
	commands []string
	address  string
	port     string
	up       bool
	mtu      int
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
	case cmd == "ip -o link show dev wg-srv1":
		flags := "BROADCAST"
		if r.up {
			flags += ",UP"
		}
		return fmt.Sprintf("8: wg-srv1: <%s> mtu %d state UP link/none\n", flags, r.mtu), nil
	case strings.HasPrefix(cmd, "ip link set dev wg-srv1 mtu "):
		_, _ = fmt.Sscan(args[5], &r.mtu)
		r.up = true
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
	runner.mtu = 1400
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "MTU 1380") {
		t.Fatalf("WireGuard MTU drift passed Health: %v", err)
	}
	runner.mtu = 1380
	runner.up = false
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "UP") {
		t.Fatalf("down WireGuard interface passed Health: %v", err)
	}
	runner.up = true
	confPath := filepath.Join(s.StateDir, "wg-srv1.conf")
	tracked := []string{
		confPath,
		s.ownedPath(),
		filepath.Join(s.ProcSysNet, "ipv6", "conf", "wg-srv1", "disable_ipv6"),
	}
	mtimes := map[string]time.Time{}
	for _, path := range tracked {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		mtimes[path] = info.ModTime()
	}
	time.Sleep(25 * time.Millisecond)
	commandStart := len(runner.commands)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	secondCommands := runner.commands[commandStart:]
	for _, command := range secondCommands {
		if strings.HasPrefix(command, "ip link add ") || strings.HasPrefix(command, "ip link set ") ||
			strings.HasPrefix(command, "ip -4 addr flush ") || strings.HasPrefix(command, "ip -4 addr add ") {
			t.Fatalf("idempotent WireGuard Apply mutated link/address: %s; all=%v", command, secondCommands)
		}
	}
	for path, before := range mtimes {
		info, err := os.Stat(path)
		if err != nil || !before.Equal(info.ModTime()) {
			t.Fatalf("idempotent WireGuard Apply changed %s: before=%v after=%v err=%v", path, before, info.ModTime(), err)
		}
	}
	ipv6Cfg := *cfg
	ipv6Cfg.IPv6.Mode = "passthrough"
	if err := s.Apply(context.Background(), &ipv6Cfg); err != nil {
		t.Fatal(err)
	}
	ipv6Path := filepath.Join(s.ProcSysNet, "ipv6", "conf", "wg-srv1", "disable_ipv6")
	if data, err := os.ReadFile(ipv6Path); err != nil || strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("IPv6 off->passthrough did not clear disable_ipv6: %q, %v", data, err)
	}
	if err := s.Health(context.Background(), &ipv6Cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipv6Path, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), &ipv6Cfg); err == nil || !strings.Contains(err.Error(), "disable_ipv6") {
		t.Fatalf("WireGuard IPv6 drift passed Health: %v", err)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(ipv6Path); err != nil || strings.TrimSpace(string(data)) != "1" {
		t.Fatalf("IPv6 passthrough->off did not set disable_ipv6: %q, %v", data, err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	originalConf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	foreignConf := filepath.Join(filepath.Dir(confPath), "foreign-wg.conf")
	if err := os.WriteFile(foreignConf, originalConf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(confPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreignConf, confPath); err == nil {
		if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("matching WireGuard symlink passed Health: %v", err)
		}
		if err := s.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Lstat(confPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("Apply did not replace WireGuard symlink: info=%v err=%v", info, err)
		}
		if data, err := os.ReadFile(foreignConf); err != nil || string(data) != string(originalConf) {
			t.Fatalf("foreign WireGuard target changed: %q, %v", data, err)
		}
	} else if err := os.WriteFile(confPath, originalConf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupt WireGuard config passed health")
	}
	if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("live drift plan=%+v err=%v", actions, err)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
		t.Fatalf("clean live plan=%+v err=%v", actions, err)
	}
	info, err := os.Stat(confPath)
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

func TestApplyHealthWithNoVPNServers(t *testing.T) {
	s, _ := newTestSubsystem(t)
	cfg := config.Default()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("empty VPN server set failed health after apply: %v", err)
	}
}
