package vpnservers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

func TestOcservUnitHistoricalIdentity(t *testing.T) {
	_, server := ocservConfig()
	server.ID = "old-server"
	before := renderOcservUnit(server, "/tmp/config")
	if !strings.Contains(before, "LogExtraFields=NETOS_VPN_SERVER_ID=old-server\n") {
		t.Fatal("missing stable identity")
	}
	path := filepath.Join(t.TempDir(), "ocserv.service")
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	server.Name = "renamed"
	if system.UnitRuntimeChanged(path, []byte(renderOcservUnit(server, "/tmp/config"))) {
		t.Fatal("rename became disruptive")
	}
	server.ID = "replacement-server"
	if !system.UnitRuntimeChanged(path, []byte(renderOcservUnit(server, "/tmp/config"))) {
		t.Fatal("replacement keeps old stream identity")
	}
	for _, id := range []string{"", ".", "..", "bad\nFIELD=x", "a b", strings.Repeat("a", 65)} {
		server.ID = id
		if strings.Contains(renderOcservUnit(server, "/tmp/config"), "LogExtraFields=") {
			t.Fatal("unsafe metadata", id)
		}
	}
}
