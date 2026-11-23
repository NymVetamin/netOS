package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
)

func previousLocalClientInterfaces(c *config.Config) map[string]bool {
	out := map[string]bool{}
	if c != nil {
		for _, n := range c.Networks {
			if n.Enabled {
				if name := c.InterfaceName(n.Interface); name != "" {
					out[name] = true
				}
			}
		}
	}
	return out
}

func TestLocalClientInterfacesEquivalence(t *testing.T) {
	if got := localClientInterfaces(nil); len(got) != 0 || got == nil {
		t.Fatalf("nil config: %v", got)
	}
	c := &config.Config{Interfaces: []config.Interface{{ID: "a", Name: "first"}, {ID: "a", Name: "second"}, {ID: "b", Name: ""}, {ID: "b", Name: "hidden"}, {ID: "", Name: "empty-id"}, {ID: "c", Name: "first", Enabled: true}}, Networks: []config.Network{{Interface: "a", Enabled: true}, {Interface: "b", Enabled: true}, {Interface: "", Enabled: true}, {Interface: "missing", Enabled: true}, {Interface: "c", Enabled: false}, {Interface: "a", Enabled: true}}}
	for shift := 0; shift < len(c.Interfaces); shift++ {
		for repeat := 0; repeat < 2; repeat++ {
			if got, want := localClientInterfaces(c), previousLocalClientInterfaces(c); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		}
		c.Interfaces = append(c.Interfaces[1:], c.Interfaces[0])
	}
	for i := range c.Networks {
		c.Networks[i].Enabled = false
	}
	if got := localClientInterfaces(c); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestClientInterfaceFilterRefreshesWithConfig(t *testing.T) {
	s := observationServer(t, &observationRunner{})
	for _, state := range []struct {
		enabled bool
		name    string
		online  bool
	}{
		{true, "br0", true}, {false, "br0", false}, {true, "br0", true}, {true, "renamed", false}, {true, "br0", true},
	} {
		s.Engine.Current().Networks[0].Enabled = state.enabled
		s.Engine.Current().Interfaces[0].Name = state.name
		w := httptest.NewRecorder()
		s.handleClients(w, httptest.NewRequest("GET", "/api/clients", nil))
		var data struct {
			Clients []struct {
				Online bool `json:"online"`
			} `json:"clients"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || len(data.Clients) != 1 || data.Clients[0].Online != state.online {
			t.Fatalf("state=%+v: %d %s", state, w.Code, w.Body.String())
		}
	}
}

func BenchmarkLocalClientInterfaces(b *testing.B) {
	for _, n := range []int{16, 2048} {
		c := config.Default()
		c.Interfaces, c.Networks = nil, nil
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("i%d", i)
			c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: fmt.Sprintf("br%d", i)})
			c.Networks = append(c.Networks, config.Network{Interface: id, Enabled: true})
		}
		b.Run(fmt.Sprintf("lookup/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if len(localClientInterfaces(c)) != n {
					b.Fatal("missing interfaces")
				}
			}
		})
		b.Run(fmt.Sprintf("clients-handler/%d", n), func(b *testing.B) {
			engine := apply.NewEngine(nil, true)
			if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
				b.Fatal(err)
			}
			engine.Current().Interfaces, engine.Current().Networks = c.Interfaces, c.Networks
			lease := filepath.Join(b.TempDir(), "leases")
			if err := os.WriteFile(lease, []byte("4102444800 aa:bb:cc:dd:ee:ff 192.168.50.10 printer *\n"), 0600); err != nil {
				b.Fatal(err)
			}
			s := &Server{Engine: engine, Collector: rt.NewCollector(&observationRunner{}, lease)}
			r := httptest.NewRequest("GET", "/api/clients", nil)
			b.ReportAllocs()
			for b.Loop() {
				w := httptest.NewRecorder()
				s.handleClients(w, r)
				if w.Code != 200 {
					b.Fatal(w.Body.String())
				}
			}
		})
	}
}
