//go:build linux

package channels

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, command := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("нет %s", command)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	encoded := base64.StdEncoding.EncodeToString(key)

	root := t.TempDir()
	s := New(system.NewExec(), root)
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	ch := config.Channel{
		ID: "integration-wg", Index: 999, Name: "Integration WireGuard", Enabled: true,
		Type: "wireguard", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"address": "192.0.2.2/32", "private_key": encoded,
			"peer_public_key": encoded, "endpoint": "192.0.2.1:51820",
			"allowed_ips": []string{"0.0.0.0/0"},
		},
	}
	cfg.Channels = append(cfg.Channels, ch)
	defer s.removeChannel(context.Background(), ownedChannel{Name: InterfaceName(ch), Index: ch.Index})

	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// Второе применение проверяет идемпотентный путь существующего интерфейса.
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}
