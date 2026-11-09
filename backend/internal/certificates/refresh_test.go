package certificates

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/tlsutil"
)

type refreshCommands struct{ calls []string }

func (r *refreshCommands) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return "", nil
}
func (r *refreshCommands) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", fmt.Errorf("unexpected input command")
}

func TestRefreshSkipsContinuesAndUsesFreshSettings(t *testing.T) {
	root := t.TempDir()
	cert, key, _, err := tlsutil.EnsureSelfSignedForNames(filepath.Join(root, "seed"), "vpn.example.test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.System.Panel.TLS = config.TLS{Mode: "custom", CertFile: cert, KeyFile: key}
	server := func(id string, index int, kind string) config.VPNServer {
		return config.VPNServer{ID: id, Index: index, Type: kind, Enabled: true, Config: map[string]any{
			"public_endpoint": "vpn.example.test:443", "tls": map[string]any{"mode": "custom", "cert_pem": string(certPEM), "private_key": string(keyPEM)},
		}}
	}
	cfg.VPNServers = []config.VPNServer{
		{ID: "disabled", Index: 1, Type: "ocserv", Config: map[string]any{"invalid": true}},
		{ID: "unmanaged", Index: 2, Type: "wireguard", Enabled: true},
		{ID: "selfsigned", Index: 3, Type: "ocserv", Enabled: true, Config: map[string]any{"tls": map[string]any{"mode": "selfsigned"}}},
		{ID: "invalid", Index: 4, Type: "ocserv", Enabled: true, Config: map[string]any{"invalid": true}},
		server("bad-host", 5, "ocserv"), server("good", 6, "ocserv"), server("xray", 7, "xray"),
	}
	cfg.VPNServers[4].Config["public_endpoint"] = "invalid endpoint"
	cfg.VPNServers[6].Config["protocol"] = "vless"
	m := New(filepath.Join(root, "manager"), nil)
	defer m.Close()
	runner := &refreshCommands{}
	dir := filepath.Join(root, "generated")
	hup := func(index int) string {
		return fmt.Sprintf("systemctl kill --kill-whom=main --signal=HUP netos-ocserv-srv%d.service", index)
	}
	for attempt := 0; attempt < 2; attempt++ {
		runner.calls = nil
		err := m.Refresh(context.Background(), cfg, dir, runner)
		if err == nil || err.Error() != "укажите публичный адрес VPN в формате домен:порт" {
			t.Fatal("first error not retained", err)
		}
		want := []string(nil)
		if attempt == 0 {
			want = []string{hup(6)}
		}
		if !slices.Equal(runner.calls, want) {
			t.Fatal("HUP selection/repeat", runner.calls)
		}
	}
	for index := 1; index <= 5; index++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("ocserv-srv%d-tls", index))); !os.IsNotExist(err) {
			t.Fatal("created files for skipped/failed server", index, err)
		}
	}
	for _, name := range []string{"ocserv-srv6-tls", "xray-srv7-tls"} {
		if _, err := os.Stat(filepath.Join(dir, name, "server.pem")); err != nil {
			t.Fatal("later valid server not processed", name, err)
		}
	}
	cfg.VPNServers[4].Config["public_endpoint"] = "vpn.example.test:443"
	runner.calls = nil
	if err := m.Refresh(context.Background(), cfg, dir, runner); err != nil || !slices.Equal(runner.calls, []string{hup(5)}) {
		t.Fatal("corrected settings not used", err, runner.calls)
	}
	runner.calls = nil
	if err := m.Refresh(context.Background(), cfg, dir, runner); err != nil || len(runner.calls) != 0 {
		t.Fatal("unchanged refresh", err, runner.calls)
	}
	if err := m.Refresh(context.Background(), nil, dir, runner); err != nil || len(runner.calls) != 0 {
		t.Fatal("nil config", err, runner.calls)
	}
}
