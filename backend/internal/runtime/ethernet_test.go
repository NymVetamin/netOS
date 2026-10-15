package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEthernetSpeedOnlyForLivePhysicalLinks(t *testing.T) {
	for _, tc := range []struct {
		name, speed, state string
		physical           bool
		want               int64
	}{
		{"gigabit", "1000", "up", true, 1000}, {"fast", "100", "up", true, 100}, {"unknown", "-1", "up", true, 0}, {"unsigned-unknown", "4294967295", "up", true, 0}, {"down", "1000", "down", true, 0}, {"virtual", "10000", "up", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "eth0")
			writeRuntimeFile(t, filepath.Join(base, "ifindex"), "2")
			writeRuntimeFile(t, filepath.Join(base, "operstate"), tc.state)
			writeRuntimeFile(t, filepath.Join(base, "speed"), tc.speed)
			writeRuntimeFile(t, filepath.Join(base, "duplex"), "full")
			if tc.physical {
				if err := os.Mkdir(filepath.Join(base, "device"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			c := NewCollector(&observationRunner{}, "")
			c.SysClassNet = root
			stats, err := c.InterfaceStats()
			if err != nil || len(stats) != 1 {
				t.Fatalf("%+v %v", stats, err)
			}
			if stats[0].SpeedMbps != tc.want {
				t.Fatalf("%+v", stats[0])
			}
			if (!tc.physical || tc.state == "down") && stats[0].Duplex != "" {
				t.Fatal("stale duplex", stats[0])
			}
		})
	}
}
