package netconf

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIfupdownCreatesVLANWithArbitraryName(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{
		{ID: "parent", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "tagged", Name: "qa-vl321", Type: "vlan", Parent: "parent", VLANID: 321, Enabled: true},
	}
	text := renderIfupdown(c)
	if !strings.Contains(text, "pre-up test -d /sys/class/net/qa-vl321 || ip link add link eth1 name qa-vl321 type vlan id 321") {
		t.Fatal("new VLAN with arbitrary name is not created before ifup")
	}
}
