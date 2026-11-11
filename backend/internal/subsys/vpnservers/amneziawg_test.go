package vpnservers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/netos-router/netos/internal/amneziawg"
	"github.com/netos-router/netos/internal/config"
)

func TestAmneziaWGServerRender(t *testing.T) {
	c := serverConfig()
	server := c.VPNServers[0]
	server.Type = "amneziawg"
	server.Config["amnezia"] = map[string]any{"h1": "100-200", "i1": "<r 8>"}
	text, err := RenderWireGuard(server)
	if err != nil {
		t.Fatal(err)
	}
	state, err := amneziawg.ParseNative(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if state.Device["h1"] != "100-200" || state.Device["listen_port"] != "51820" || len(state.Peers) != 1 {
		t.Fatal("server configuration lost")
	}
	if InterfaceName(server) != "awg-srv1" || ownedServersFor(c.VPNServers)[0].Unit != "" {
		t.Fatal("ordinary WG ownership changed")
	}
	c.VPNServers[0] = server
	if ownedServersFor(c.VPNServers)[0].Unit != "netos-awg-srv1.service" {
		t.Fatal("AWG unit not owned")
	}
	server.Peers[0].Enabled = false
	text, err = RenderWireGuard(server)
	if err != nil {
		t.Fatal(err)
	}
	state, err = amneziawg.ParseNative(context.Background(), text)
	if err != nil || len(state.Peers) != 0 {
		t.Fatal("disabled peer retained", err)
	}
	server.Type = "wireguard"
	if _, err = RenderWireGuard(server); err == nil {
		t.Fatal("ordinary WG accepted AWG options")
	}
}

func BenchmarkAmneziaWGServerPreparation(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := serverConfig().VPNServers[0]
			s.Type = "amneziawg"
			s.Peers = nil
			for i := 0; i < n; i++ {
				key := make([]byte, 32)
				binary.BigEndian.PutUint64(key, uint64(i+1))
				s.Peers = append(s.Peers, config.VPNPeer{Enabled: true, Address: fmt.Sprintf("10.20.%d.%d", i/256, i%256), Credentials: map[string]string{"public_key": base64.StdEncoding.EncodeToString(key)}})
			}
			text, err := RenderWireGuard(s)
			if err != nil {
				b.Fatal(err)
			}
			live, err := amneziawg.ParseNative(context.Background(), text)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				text, err := RenderWireGuard(s)
				if err != nil {
					b.Fatal(err)
				}
				want, err := amneziawg.ParseNative(context.Background(), text)
				if err != nil {
					b.Fatal(err)
				}
				if amneziawg.Delta(want, live) != "" {
					b.Fatal("no-op changed state")
				}
			}
		})
	}
}
