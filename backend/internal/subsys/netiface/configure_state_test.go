package netiface

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestConfigureSnapshotMatchesRecursiveStates(t *testing.T) {
	c := &config.Config{Interfaces: []config.Interface{
		{ID: "root", Enabled: true}, {ID: "off", Enabled: false},
		{ID: "v1", Type: "vlan", Parent: "root", Enabled: true}, {ID: "v2", Type: "vlan", Parent: "v1", Enabled: true},
		{ID: "blocked", Type: "vlan", Parent: "off", Enabled: true}, {ID: "missing", Type: "vlan", Parent: "absent", Enabled: true},
		{ID: "cycle1", Type: "vlan", Parent: "cycle2", Enabled: true}, {ID: "cycle2", Type: "vlan", Parent: "cycle1", Enabled: true},
		{ID: "root", Enabled: false}, {ID: "", Enabled: true},
	}}
	for range len(c.Interfaces) {
		states := c.InterfaceStates()
		for _, iface := range c.Interfaces {
			if states[iface.ID] != c.InterfaceEnabled(iface.ID) {
				t.Fatalf("state differs for %q", iface.ID)
			}
		}
		c.Interfaces = append(c.Interfaces[1:], c.Interfaces[0])
	}
}

func TestApplyInterfaceStateRefreshAndRetry(t *testing.T) {
	newFakeNet(t, "one", "two")
	var commands []string
	fail := false
	r := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		commands = append(commands, cmd)
		if fail && cmd == "ip link set one down" {
			return "", fmt.Errorf("injected")
		}
		return "", nil
	})
	s := NewInterfaces(r)
	s.OwnedPath = filepath.Join(t.TempDir(), "owned")
	c := &config.Config{Interfaces: []config.Interface{{ID: "same", Name: "one", Type: "physical", Enabled: true}, {ID: "same", Name: "two", Type: "physical", Enabled: false}}}
	for _, on := range []bool{true, false, true} {
		c.Interfaces[0].Enabled = on
		if !on {
			fail = true
			if err := s.Apply(context.Background(), c); err == nil {
				t.Fatal("command failure hidden")
			}
			fail = false
		}
		for range 2 {
			commands = nil
			if err := s.Apply(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			state := "down"
			if on {
				state = "up"
			}
			for _, name := range []string{"one", "two"} {
				if !slices.Contains(commands, "ip link set "+name+" "+state) {
					t.Fatal("stale or non-first state", commands)
				}
			}
		}
	}
}

func BenchmarkApplyInterfaceStates(b *testing.B) {
	for _, n := range []int{16, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			root := b.TempDir()
			oldNet, oldVLAN := sysClassNet, procNetVLAN
			sysClassNet, procNetVLAN = filepath.Join(root, "net"), filepath.Join(root, "vlan")
			b.Cleanup(func() { sysClassNet, procNetVLAN = oldNet, oldVLAN })
			c := &config.Config{}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("eth%d", i)
				if err := os.MkdirAll(filepath.Join(sysClassNet, name), 0755); err != nil {
					b.Fatal(err)
				}
				c.Interfaces = append(c.Interfaces, config.Interface{ID: name, Name: name, Type: "physical", Enabled: true})
			}
			r := &linkRunner{}
			s := NewInterfaces(r)
			s.OwnedPath = filepath.Join(root, "owned")
			ctx := context.Background()
			if err := s.Apply(ctx, c); err != nil {
				b.Fatal(err)
			}
			calls := 0
			b.ReportAllocs()
			for b.Loop() {
				r.commands = nil
				if err := s.Apply(ctx, c); err != nil {
					b.Fatal(err)
				}
				calls += len(r.commands)
			}
			b.ReportMetric(float64(calls)/float64(b.N), "commands/op")
		})
	}
}
