package wifi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHealthWaitsForEverySSIDBridgePort(t *testing.T) {
	root := t.TempDir()
	s := New(&fakeRunner{}, filepath.Join(root, "state"))
	s.UnitDir = filepath.Join(root, "units")
	s.SysClassNet = filepath.Join(root, "net")
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	writeState := func(device, state string) {
		t.Helper()
		dir := filepath.Join(s.SysClassNet, device, "brport")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state"), []byte(state), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeState("wlan0", "3\n")
	writeState("wlan0-n1", "3\n")
	for _, device := range []string{"wlan0", "wlan0-n1"} {
		for _, state := range []string{"0", "1", "2", "4"} {
			writeState(device, state)
			if err := s.health(context.Background(), cfg, 1); err == nil {
				t.Fatalf("AP with %s bridge state %s was declared ready", device, state)
			}
		}
		writeState(device, "3\n")
	}
	if err := s.health(context.Background(), cfg, 1); err != nil {
		t.Fatalf("forwarding AP rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(s.SysClassNet, "wlan0-n1", "brport", "state")); err != nil {
		t.Fatal(err)
	}
	if err := s.health(context.Background(), cfg, 1); err == nil {
		t.Fatal("AP with unreadable bridge state was declared ready")
	}
}
