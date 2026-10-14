package socks

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fake struct {
	active bool
	fail   string
	calls  []string
}

func (f *fake) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.fail != "" && strings.Contains(cmd, f.fail) {
		return "", fmt.Errorf("injected failure")
	}
	if strings.Contains(cmd, "systemctl stop") {
		f.active = false
	}
	if strings.Contains(cmd, "systemctl restart") {
		f.active = true
	}
	if strings.Contains(cmd, "is-active") {
		if f.active {
			return "active", nil
		}
		return "inactive", nil
	}
	return "", nil
}
func (f *fake) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f.Run(ctx, name, args...)
}
func fixture() *config.Config {
	c := config.Default()
	c.Socks = config.Socks{Enabled: true, Port: 1080, Auth: true, Username: "test", Password: "test-password", Channel: "direct"}
	return c
}
func TestSocksRenderAndLifecycle(t *testing.T) {
	c := fixture()
	f := &fake{}
	root := t.TempDir()
	s := &Subsystem{Runner: f, StateDir: filepath.Join(root, "generated"), UnitDir: filepath.Join(root, "units")}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.StateDir, "socks.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"protocol": "socks"`, `"auth": "password"`, `"udp": false`, `"ForceIPv4"`, `"::/0"`} {
		if !strings.Contains(string(data), want) {
			t.Fatal(want)
		}
	}
	if strings.Contains(strings.Join(f.calls, " "), "systemctl enable") {
		t.Fatal("proxy starts before firewall at boot")
	}
	c.Socks.Port = 1081
	if err := (&Preparation{S: s}).Apply(ctx, c); err != nil || f.active {
		t.Fatal("listener not stopped before firewall change")
	}
	f.fail = "-test"
	if err := s.Apply(ctx, c); err == nil {
		t.Fatal("invalid config accepted")
	}
	f.fail = ""
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Socks.Enabled = false
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if f.active {
		t.Fatal("listener left active")
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, Unit)); !os.IsNotExist(err) {
		t.Fatal("unit left behind")
	}
}
func TestSocksNeverFallsBackForMissingChannel(t *testing.T) {
	c := fixture()
	c.Socks.Channel = "missing"
	if _, err := Render(c); err == nil {
		t.Fatal("missing channel silently became direct")
	}
	c.Channels = append(c.Channels, config.Channel{ID: "vpn", Enabled: true, Type: "xray", Index: 2})
	c.Socks.Channel = "vpn"
	data, err := Render(c)
	if err != nil || !strings.Contains(string(data), `"mark":`) {
		t.Fatal(string(data), err)
	}
}

func TestSocksStartsAfterFirewall(t *testing.T) {
	positions := map[string]int{}
	for i, name := range apply.Order {
		positions[name] = i
	}
	if positions["socks-prepare"] >= positions["firewall"] || positions["socks"] <= positions["firewall"] {
		t.Fatal("unsafe SOCKS lifecycle ordering")
	}
}
