package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitRuntimeChanged(t *testing.T) {
	base := "[Unit]\nDescription=Before\nAfter=network.target\n[Service]\nExecStart=/bin/sleep 100\n"
	for _, tc := range []struct {
		name, before, after string
		changed             bool
	}{
		{"same", base, base, false},
		{"description", base, strings.Replace(base, "Description=Before", "Description=After", 1), false},
		{"command", base, strings.Replace(base, "sleep 100", "sleep 200", 1), true},
		{"dependency", base, strings.Replace(base, "network.target", "network-online.target", 1), true},
		{"missing description", base, strings.Replace(base, "Description=Before\n", "", 1), true},
		{"continuation", base, strings.Replace(base, "Description=Before", "Description=After\\", 1), true},
		{"old continuation", strings.Replace(base, "Description=Before", "Description=Before\\", 1), base, true},
		{"wrong section", "[Service]\nDescription=Before\n", "[Service]\nDescription=After\n", true},
		{"unknown directive", base, base + "Unrecognized=1\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "qa.service")
			if err := os.WriteFile(path, []byte(tc.before), 0600); err != nil {
				t.Fatal(err)
			}
			if got := UnitRuntimeChanged(path, []byte(tc.after)); got != tc.changed {
				t.Fatalf("changed=%v want=%v", got, tc.changed)
			}
		})
	}
	if !UnitRuntimeChanged(filepath.Join(t.TempDir(), "missing"), []byte(base)) {
		t.Fatal("missing file accepted")
	}
}
