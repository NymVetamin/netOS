package manage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallRestoresIfupdownBeforeRestart(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	original := "auto lo\niface lo inet loopback\nallow-hotplug eth0\niface eth0 inet dhcp\n"
	applied := "auto lo\niface lo inet loopback\nsource /etc/network/interfaces.d/netos.conf\n"
	main := filepath.Join(m.Root, "etc/network/interfaces")
	generated := filepath.Join(m.Root, "etc/network/interfaces.d/netos.conf")
	journal := filepath.Join(m.Root, "var/lib/netos-system-baseline/ifupdown.json")
	data, err := json.Marshal(map[string]any{"/etc/network/interfaces": map[string]any{"original": []byte(original), "applied": []byte(applied), "mode": 0644, "exists": true}})
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{main: []byte(applied), generated: []byte("auto eth0\niface eth0 inet manual\n"), journal: data} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	restarted := false
	m.Run = func(_ context.Context, c command) error {
		if c.name == "systemctl" && len(c.args) == 2 && c.args[0] == "restart" && c.args[1] == "networking" {
			restarted = true
			data, err := os.ReadFile(main)
			if err != nil || string(data) != original {
				t.Fatalf("networking restarted before original returned: %s %v", data, err)
			}
		}
		return nil
	}
	if err := m.uninstall(context.Background(), true, false, false, true); err != nil {
		t.Fatal(err)
	}
	if !restarted {
		t.Fatal("networking was not restarted")
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("journal remains", err)
	}
}
