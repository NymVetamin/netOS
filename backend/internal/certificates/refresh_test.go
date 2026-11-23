package certificates

import (
	"context"
	"errors"
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

func TestRefreshRemovesOnlyDeletedVPNStatus(t *testing.T) {
	root := t.TempDir()
	m := New(filepath.Join(root, "manager"), nil)
	defer m.Close()
	cfg := config.Default()
	cfg.System.Hostname = "router"
	server := config.VPNServer{ID: "old", Index: 1, Type: "ocserv", Enabled: true, Config: map[string]any{
		"public_endpoint": "router:443", "tls": map[string]any{"mode": "panel"},
	}}
	cfg.VPNServers = []config.VPNServer{server}
	r := &refreshCommands{}
	refresh := func() {
		t.Helper()
		if err := m.Refresh(context.Background(), cfg, filepath.Join(root, "generated"), r); err != nil {
			t.Fatal(err)
		}
	}
	refresh()
	if len(m.Status()) != 2 {
		t.Fatal("initial statuses", m.Status())
	}
	if err := m.Refresh(context.Background(), nil, "", r); err != nil || len(m.Status()) != 2 {
		t.Fatal("nil refresh changed status", err)
	}
	cfg.VPNServers[0].ID = "new"
	refresh()
	for _, status := range m.Status() {
		if status.Domain == "vpn:old" {
			t.Fatal("deleted VPN retained status")
		}
	}
	// A retained disabled VPN keeps its last error and published certificate.
	m.record("vpn:new", nil, errors.New("publication failed"))
	cfg.VPNServers[0].Enabled = false
	refresh()
	if len(m.Status()) != 2 {
		t.Fatal("cleanup removed a configured VPN", m.Status())
	}
	for _, status := range m.Status() {
		if status.Domain == "vpn:new" && (status.Error == "" || status.Fingerprint == "") {
			t.Fatal("cleanup erased an existing VPN's status", status)
		}
	}
	cfg.VPNServers = nil
	for range 2 {
		refresh()
		if states := m.Status(); len(states) != 1 || states[0].Domain != "panel" {
			t.Fatal("removed VPN status remains", states)
		}
	}
	cfg.VPNServers = []config.VPNServer{server}
	refresh()
	if len(m.Status()) != 2 {
		t.Fatal("re-added VPN has no fresh status", m.Status())
	}
	for _, status := range m.Status() {
		if status.Error != "" || status.Fingerprint == "" {
			t.Fatal("re-added VPN retained stale state", status)
		}
	}
}

func (r *refreshCommands) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return "", nil
}

type failingReload struct {
	refreshCommands
	err error
}

func (r *failingReload) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.refreshCommands.Run(ctx, name, args...)
	return "", r.err
}

func TestRefreshRetriesUnfinishedReload(t *testing.T) {
	root := t.TempDir()
	managerDir := filepath.Join(root, "manager")
	generated := filepath.Join(root, "generated")
	m := New(managerDir, nil)
	ctx := context.Background()
	cfg := config.Default()
	cfg.System.Hostname = "old"
	server := config.VPNServer{Type: "ocserv", ID: "vpn", Index: 1, Enabled: true, Config: map[string]any{
		"public_endpoint": "old:443", "tls": map[string]any{"mode": "panel"},
	}}
	cfg.VPNServers = []config.VPNServer{server}
	r := &failingReload{}
	if err := m.Refresh(ctx, cfg, generated, r); err != nil || len(r.calls) != 1 {
		t.Fatal("initial reload", err, r.calls)
	}
	cfg.System.Hostname = "new"
	server.Config["public_endpoint"] = "new:443"
	dir := filepath.Join(generated, "ocserv-srv1-tls")
	pub := filepath.Join(dir, "panel.crt")
	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pub, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(ctx, cfg, generated, r); err == nil || len(r.calls) != 1 {
		t.Fatal("reload before public export", err, r.calls)
	}
	bundle := filepath.Join(dir, "server.pem")
	if _, err := ReadPair(bundle, bundle, "new"); err != nil {
		t.Fatal("new bundle must already be on disk", err)
	}
	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}
	r.err = errors.New("HUP failed")
	for i := 0; i < 2; i++ {
		m = New(managerDir, nil)
		if err := m.Refresh(ctx, cfg, generated, r); !errors.Is(err, r.err) || len(r.calls) != 2+i {
			t.Fatal("missing retry after restart", err, r.calls)
		}
	}
	r.err = nil
	for i := 0; i < 2; i++ {
		if err := m.Refresh(ctx, cfg, generated, r); err != nil || len(r.calls) != 4 {
			t.Fatal("expected one successful retry", err, r.calls)
		}
	}
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
