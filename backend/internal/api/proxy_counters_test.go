package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	rt "github.com/netos-router/netos/internal/runtime"
)

func TestProxyCountersPreserveNestedJoinSemantics(t *testing.T) {
	peers := []config.VPNPeer{{ID: "b", Name: "B"}, {ID: "a", Name: "A"}, {ID: "b", Name: "second B"}}
	rows := []vpnClientStatus{{ID: "a", TrafficKnown: true, Sent: 19, Received: 31}, {ID: "b", TrafficKnown: false, Sent: 999}, {ID: "missing", TrafficKnown: true}, {ID: "b", TrafficKnown: true, Sent: 0, Received: 42}}
	for _, name := range []string{"original", "renamed"} {
		cfg := &config.Config{VPNServers: []config.VPNServer{
			{ID: "one", Name: name, Type: "xray", Enabled: true, Peers: peers},
			{ID: "two", Name: "other", Type: "xray", Enabled: true, Peers: peers},
			{ID: "off", Type: "xray", Enabled: false, Peers: peers},
			{ID: "wg", Type: "wireguard", Enabled: true, Peers: peers},
		}}
		s := &Server{vpnStatus: map[string]*vpnStatusCache{}}
		at := time.Unix(100, 123)
		want := []rt.ClientCounter{}
		for _, server := range cfg.VPNServers {
			encoded, err := json.Marshal(server)
			if err != nil {
				t.Fatal(err)
			}
			s.vpnStatus[server.ID] = &vpnStatusCache{fingerprint: sha256.Sum256(encoded), rows: rows, at: at}
			if !server.Enabled || server.Type != "xray" {
				continue
			}
			// Independent reference: the previous ordered nested join.
			for _, row := range rows {
				if !row.TrafficKnown {
					continue
				}
				for _, peer := range server.Peers {
					if peer.ID == row.ID {
						want = append(want, rt.ClientCounter{ID: "vpn:" + server.ID + ":" + peer.ID, Name: peer.Name + " · " + server.Name, Address: "xray:" + server.ID + ":" + peer.ID, RX: row.Sent, TX: row.Received, SampledAt: at})
					}
				}
			}
		}
		if got := s.ProxyClientCounters(context.Background(), cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("counter identity/order/direction changed:\ngot=%+v\nwant=%+v", got, want)
		}
	}
}
