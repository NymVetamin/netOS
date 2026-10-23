package config

import (
	"reflect"
	"testing"
)

func TestComponentSelectionCanonicalForm(t *testing.T) {
	for _, info := range Catalog {
		c := Default()
		c.Components = []Component{{ID: info.ID, Installed: true}}
		c.Normalize()
		if !c.HasComponent(info.ID) {
			t.Fatalf("selected %s lost", info.ID)
		}
		c.Components[0].Installed = false
		c.Normalize()
		if len(c.Components) != 0 {
			t.Fatalf("unselected %s remains", info.ID)
		}
	}
	input := []Component{{ID: "xray", Installed: true}, {ID: "dnsmasq", Installed: false}, {ID: "wireguard", Installed: true}}
	c := Default()
	c.Components = input
	c.Normalize()
	if len(c.Components) != 2 || c.Components[0].ID != "wireguard" || c.Components[1].ID != "xray" {
		t.Fatal(c.Components)
	}
	if input[0].ID != "xray" || len(input) != 3 {
		t.Fatal("normalization mutated source slice")
	}
	for _, invalid := range [][]Component{
		{{ID: "unknown", Installed: false}},
		{{ID: "xray", Installed: false}, {ID: "xray", Installed: true}},
	} {
		c.Components = invalid
		c.Normalize()
		if !reflect.DeepEqual(c.Components, invalid) || !c.Validate().HasErrors() {
			t.Fatal("invalid components hidden")
		}
	}
}
