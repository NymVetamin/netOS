package netiface

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestInterfaceApplyLookupMatchesConfig(t *testing.T) {
	cfg := &config.Config{Interfaces: []config.Interface{
		{ID: "a", Name: "same", Enabled: true}, {ID: "b", Name: "same", Enabled: false}, {ID: "a", Name: "second", Enabled: false},
		{ID: "off", Name: "off"}, {ID: "v", Name: "v", Enabled: true, Type: "vlan", Parent: "off"},
		{ID: "cycle", Name: "cycle", Enabled: true, Type: "vlan", Parent: "cycle"}, {ID: "", Name: "empty", Enabled: true}, {ID: "blank", Name: ""},
	}}
	ids := []string{"a", "v", "missing", "a", "", "cycle", "blank", "b"}
	cfg.Interfaces[0].Members = ids
	for range len(cfg.Interfaces) {
		lookup := newInterfaceApplyLookup(cfg)
		if !reflect.DeepEqual(lookup.names(ids), cfg.InterfaceNames(ids)) {
			t.Fatal("name order or duplicates changed")
		}
		for _, iface := range cfg.Interfaces {
			if lookup.enabled[iface.ID] != cfg.InterfaceEnabled(iface.ID) || lookup.enabledNames[iface.Name] != cfg.InterfaceNameEnabled(iface.Name) {
				t.Fatalf("state differs: %+v", iface)
			}
		}
		cfg.Interfaces = append(cfg.Interfaces[1:], cfg.Interfaces[0])
	}
}
func TestApplyBridgeMemberStateRefreshAndRetry(t *testing.T) {
	newFakeNet(t, "br0:bridge", "p0", "p1")
	fail := false
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		commands = append(commands, cmd)
		if fail && cmd == "ip link set p0 up" {
			return "", fmt.Errorf("injected member failure")
		}
		return "", nil
	})
	cfg := &config.Config{Interfaces: []config.Interface{{ID: "a", Name: "p0", Type: "physical", Enabled: true}, {ID: "b", Name: "p1", Type: "physical"}, {ID: "br", Name: "br0", Type: "bridge", Enabled: true, MAC: "02:00:00:00:00:01", Members: []string{"b", "a"}}}}
	s := NewInterfaces(runner)
	s.OwnedPath = filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(s.OwnedPath, []byte("br0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{true, false, true} {
		cfg.Interfaces[0].Enabled = on
		if on {
			fail = true
			if err := s.Apply(context.Background(), cfg); err == nil {
				t.Fatal("member failure hidden")
			}
			fail = false
		}
		for range 2 {
			commands = nil
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(commands, "\n")
			state := "down"
			if on {
				state = "up"
			}
			if !strings.Contains(joined, "ip link set p0 master br0\nip link set p0 "+state) || !strings.Contains(joined, "ip link set p1 master br0\nip link set p1 down") {
				t.Fatal("member state or order changed", joined)
			}
			if strings.Index(joined, "p1 master") > strings.Index(joined, "p0 master") {
				t.Fatal("member order changed")
			}
		}
	}
}

func BenchmarkBridgeLookupPreparation(b *testing.B) {
	for _, n := range []int{16, 512} {
		for _, indexed := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/indexed%t", n, indexed), func(b *testing.B) {
				cfg := &config.Config{}
				ids := []string{}
				for i := 0; i < n; i++ {
					id := fmt.Sprint(i)
					cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: id, Name: "eth" + id, Enabled: true})
					ids = append(ids, id)
				}
				cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: "br", Name: "br0", Type: "bridge", Members: ids})
				b.ReportAllocs()
				for b.Loop() {
					count := 0
					if indexed {
						lookup := newInterfaceApplyLookup(cfg)
						members := lookup.names(ids)
						for _, name := range members {
							if lookup.enabledNames[name] {
								count++
							}
						}
						count += len(members)
					} else {
						states := cfg.InterfaceStates()
						if !states["0"] {
							b.Fatal("state")
						}
						for _, name := range cfg.InterfaceNames(ids) {
							if cfg.InterfaceNameEnabled(name) {
								count++
							}
						}
						count += len(cfg.InterfaceNames(ids))
					}
					if count != 2*n {
						b.Fatal(count)
					}
				}
			})
		}
	}
}
