package netconf

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPassivePassthroughExplicitlyEnablesLinkLocal(t *testing.T) {
	iface := config.Interface{Name: "eth1", Type: "physical", Enabled: true}
	for _, off := range []bool{false, true} {
		text := renderPassive(iface, off)
		want := "LinkLocalAddressing=ipv6\n"
		if off {
			want = "LinkLocalAddressing=no\n"
		}
		if !strings.Contains(text, want) || !strings.Contains(text, "KeepMaster=yes\n") {
			t.Fatalf("IPv6 off=%v: explicit link-local policy or master preservation missing:\n%s", off, text)
		}
	}
}
