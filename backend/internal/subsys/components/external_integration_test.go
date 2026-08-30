//go:build linux

package components

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

// This test deliberately exercises the official release download as well as
// the real systemd/TUN lifecycle. It only runs explicitly on a disposable
// Linux integration host and restores the host to its original state.
func TestIntegrationXrayInstallAndLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	rel := externalReleases["xray"]
	if _, err := os.Stat(rel.Target); err == nil {
		t.Skipf("refusing to overwrite an existing %s", rel.Target)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}

	ctx := context.Background()
	componentSubsystem := New(system.NewExec(), quietLogger{})
	if err := componentSubsystem.installRelease(ctx, "xray", rel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(rel.Target) })
	if output, err := system.NewExec().Run(ctx, rel.Target, "version"); err != nil || !strings.Contains(output, "Xray") {
		t.Fatalf("installed Xray cannot run: %q (%v)", output, err)
	}

	// The service has PrivateTmp=true, so a config below testing.T's /tmp
	// directory is intentionally invisible to it.
	root, err := os.MkdirTemp("/var/lib", "netos-xray-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	channelSubsystem := channels.New(system.NewExec(), root)
	channelSubsystem.RTTablesPath = filepath.Join(root, "rt_tables")
	channel := config.Channel{
		ID: "integration-xray-install", Index: 996, Name: "Integration Xray", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"mtu":      1380,
			"outbound": map[string]any{"protocol": "freedom", "settings": map[string]any{}},
		},
	}
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "xray", Installed: true}}
	cfg.Channels = append(cfg.Channels, channel)
	t.Cleanup(func() { _ = channelSubsystem.Apply(context.Background(), config.Default()) })

	if err := channelSubsystem.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := channelSubsystem.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if output, err := system.NewExec().Run(ctx, "systemctl", "is-active", "netos-xray-ch996.service"); err != nil || strings.TrimSpace(output) != "active" {
		t.Fatalf("Xray service is not active: %q (%v)", output, err)
	}
	routes, err := system.NewExec().Run(ctx, "ip", "-4", "route", "show", "table", "1996")
	if err != nil || !strings.Contains(routes, "default dev tun-ch996") || !strings.Contains(routes, "blackhole default") {
		t.Fatalf("incomplete Xray routing table: %q (%v)", routes, err)
	}
	// Binding curl to the TUN proves that packets traverse Xray's userspace
	// stack and its outbound, rather than merely observing a created device.
	if output, err := system.NewExec().Run(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "15", "--interface", "tun-ch996", "https://1.1.1.1/cdn-cgi/trace"); err != nil || !strings.Contains(output, "ip=") {
		t.Fatalf("traffic did not pass through Xray TUN: %q (%v)", output, err)
	}

	if err := channelSubsystem.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", "netos-xray-ch996.service")); !os.IsNotExist(err) {
		t.Fatalf("Xray unit was not removed: %v", err)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	public := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	server := config.VPNServer{
		ID: "integration-reality", Index: 997, Name: "Integration Reality", Enabled: true, Type: "xray",
		Subnet: "10.97.0.1/24", Port: 18443, DefaultChannel: "direct",
		Config: map[string]any{
			"private_key": private, "public_endpoint": "127.0.0.1:18443", "destination": "www.cloudflare.com:443",
			"server_names": []string{"www.cloudflare.com"}, "short_ids": []string{"0123456789abcdef"}, "flow": "xtls-rprx-vision", "show": true,
		},
		Peers: []config.VPNPeer{{
			ID: "client", Name: "Integration client", Enabled: true, Address: "10.97.0.2",
			Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"},
		}},
	}
	serverCfg := config.Default()
	serverCfg.Components = []config.Component{{ID: "xray", Installed: true}}
	serverCfg.VPNServers = []config.VPNServer{server}
	serverSubsystem := vpnservers.New(system.NewExec(), root)
	t.Cleanup(func() { _ = serverSubsystem.Apply(context.Background(), config.Default()) })
	if err := serverSubsystem.Apply(ctx, serverCfg); err != nil {
		t.Fatal(err)
	}
	if err := serverSubsystem.Health(ctx, serverCfg); err != nil {
		t.Fatal(err)
	}

	clientDoc := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": 19080, "protocol": "socks", "settings": map[string]any{"udp": true},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": 18443, "users": []any{map[string]any{
					"id": "123e4567-e89b-12d3-a456-426614174000", "encryption": "none", "flow": "xtls-rprx-vision",
				}},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{"show": true, "serverName": "www.cloudflare.com", "fingerprint": "chrome", "password": public, "shortId": "0123456789abcdef"},
			},
		}},
	}
	clientData, err := json.Marshal(clientDoc)
	if err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "reality-client.json")
	if err := os.WriteFile(clientPath, clientData, 0o600); err != nil {
		t.Fatal(err)
	}
	var clientLog bytes.Buffer
	client := exec.Command(rel.Target, "run", "-config", clientPath)
	client.Stdout, client.Stderr = &clientLog, &clientLog
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
	})
	var traffic string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		traffic, err = system.NewExec().Run(ctx, "curl", "--fail", "--silent", "--show-error", "--max-time", "3", "--socks5-hostname", "127.0.0.1:19080", "https://1.1.1.1/cdn-cgi/trace")
		if err == nil && strings.Contains(traffic, "ip=") {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil || !strings.Contains(traffic, "ip=") {
		t.Fatalf("traffic did not pass through VLESS Reality: %q (%v); client=%s", traffic, err, clientLog.String())
	}
	_ = client.Process.Kill()
	_, _ = client.Process.Wait()
	if err := serverSubsystem.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", "netos-xray-srv997.service")); !os.IsNotExist(err) {
		t.Fatalf("Xray server unit was not removed: %v", err)
	}
}
