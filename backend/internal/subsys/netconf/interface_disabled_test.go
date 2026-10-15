package netconf

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestDisabledPortPersistsAcrossBackends(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "p", Name: "qa0", Type: "physical", Enabled: false}, {ID: "v", Name: "qa7", Type: "vlan", Parent: "p", VLANID: 7, Enabled: true}, {ID: "b", Name: "br-qa", Type: "bridge", Members: []string{"p"}, Enabled: true}}
	for _, files := range []map[string]string{renderNetworkd(c), passiveFiles(c.RuntimeNetworkConfig())} {
		for _, name := range []string{"qa0", "qa7"} {
			found := false
			for filename, data := range files {
				if strings.HasSuffix(filename, name+".network") {
					found = true
					if !strings.Contains(data, "ActivationPolicy=always-down") {
						t.Fatal(filename, data)
					}
				}
			}
			if !found {
				t.Fatal(name)
			}
		}
	}
	text := renderIfupdown(c)
	for _, bad := range []string{"auto qa0", "auto qa7", "bridge_ports qa0", "up ip link set dev qa0 up"} {
		if strings.Contains(text, bad) {
			t.Fatal(text)
		}
	}
	if !strings.Contains(text, "iface qa0 inet manual") {
		t.Fatal("disabled interface inventory lost")
	}
}
