//go:build linux

package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The fixture contains complete logs from two isolated dnsproxy releases,
// each answering one netos-fixture.invalid question through its hosts file.
func TestIntegrationDNSProxyRecordedLogs(t *testing.T) {
	path := os.Getenv("NETOS_DNS_LOG_PROOF")
	if path == "" {
		t.Skip("requires captured real dnsproxy query logs")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Version string
		Log     string
	}
	if err = json.Unmarshal(data, &fixtures); err != nil || len(fixtures) != 2 {
		t.Fatal(err, len(fixtures))
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dns.log")
			if err := os.WriteFile(path, []byte(fixture.Log), 0600); err != nil {
				t.Fatal(err)
			}
			rows, err := readDNSLog(path, time.Now())
			if err != nil || len(rows) != 1 || rows[0].Time == "" || !strings.Contains(rows[0].Message, ";netos-fixture.invalid.") {
				t.Fatal(rows, err)
			}
			repeated, err := readDNSLog(path, time.Now())
			if err != nil || !reflect.DeepEqual(rows, repeated) {
				t.Fatal("repeat changed", err)
			}
			var raw strings.Builder
			for _, line := range strings.Split(fixture.Log, "\n") {
				row, _ := json.Marshal(map[string]string{"MESSAGE": line, "_SYSTEMD_UNIT": "netos-dnsproxy.service", "__REALTIME_TIMESTAMP": "1794577055662033"})
				raw.Write(row)
				raw.WriteByte('\n')
			}
			journal, err := parseJournalEntries(raw.String(), "dns")
			if err != nil || len(journal) != 1 || journal[0].Message != rows[0].Message {
				t.Fatal(journal, err)
			}
			t.Logf("one incoming query retained from %d real lines; replies and lifecycle excluded", strings.Count(fixture.Log, "\n"))
		})
	}
}
