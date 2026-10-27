package api

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"strings"
	"testing"
)

func BenchmarkVPNSessionConfig(b *testing.B) {
	for _, kind := range []string{"xray", "ocserv"} {
		for _, count := range []int{1, 50, 200} {
			b.Run(fmt.Sprintf("%s/%d", kind, count), func(b *testing.B) {
				server := config.VPNServer{ID: "srv", Type: kind, Index: 2, Enabled: true}
				out := "{}"
				if kind == "xray" {
					server.Config = map[string]any{"protocol": "reality", "server_names": []string{"vpn.example.test"}}
				} else {
					out = "[]"
					server.Config = map[string]any{"auth_mode": "certificate", "banner": strings.Repeat("x", 2048)}
				}
				for i := 0; i < count; i++ {
					server.Peers = append(server.Peers, config.VPNPeer{ID: fmt.Sprint(i), Enabled: true})
				}
				runner := &sessionRunner{out: out}
				s := &Server{Collector: &runtime.Collector{Runner: runner}}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					runner.calls = nil
					if len(s.sessionClients(context.Background(), server)) != count {
						b.Fatal("missing rows")
					}
				}
			})
		}
	}
}

func TestSessionConfigIdentityAndFailures(t *testing.T) {
	for _, tc := range []struct {
		kind            string
		cfg             map[string]any
		identity, state string
	}{
		{"xray", nil, "srv/phone", "online"},
		{"xray", map[string]any{"protocol": "socks"}, "alice", "online"},
		{"xray", map[string]any{"protocol": "http"}, "alice", "online"},
		{"xray", map[string]any{"protocol": "reality"}, "srv/phone", "online"},
		{"xray", map[string]any{"protocol": 42}, "srv/phone", "unknown"},
		{"xray", map[string]any{"unexpected": true}, "srv/phone", "unknown"},
		{"ocserv", nil, "alice", "online"},
		{"ocserv", map[string]any{"auth_mode": "password"}, "alice", "online"},
		{"ocserv", map[string]any{"auth_mode": "certificate"}, "netos-phone", "online"},
		{"ocserv", map[string]any{"auth_mode": "certificate_password"}, "netos-phone", "online"},
		{"ocserv", map[string]any{"auth_mode": "certificate", "unexpected": true}, "netos-phone", "online"},
		{"ocserv", map[string]any{"auth_mode": 42}, "alice", "online"},
	} {
		t.Run(fmt.Sprintf("%s/%v", tc.kind, tc.cfg), func(t *testing.T) {
			out := fmt.Sprintf(`{"users":[{"email":%q,"ips":[{"ip":"192.0.2.7"}],"traffic":{"uplink":123,"downlink":456}}]}`, tc.identity)
			if tc.kind == "ocserv" {
				out = fmt.Sprintf(`[{"Username":%q,"State":"connected","Remote IP":"192.0.2.7","RX":"123","TX":"456"}]`, tc.identity)
			}
			r := &sessionRunner{out: out}
			s := &Server{Collector: &runtime.Collector{Runner: r}}
			server := config.VPNServer{ID: "srv", Index: 2, Type: tc.kind, Enabled: true, Config: tc.cfg, Peers: []config.VPNPeer{{ID: "phone", Enabled: true, Credentials: map[string]string{"username": "alice"}}, {ID: "disabled"}, {ID: "absent", Enabled: true}}}
			rows := s.sessionClients(context.Background(), server)
			if rows[0].State != tc.state || rows[1].State != "disabled" || rows[2].State == "online" {
				t.Fatalf("bad states: %+v", rows)
			}
			if tc.state == "online" && (rows[0].Received != 123 || rows[0].Sent != 456 || rows[0].Endpoint != "192.0.2.7" || !rows[0].TrafficKnown) {
				t.Fatalf("lost telemetry: %+v", rows)
			}
			r.fail = true
			if rows = s.sessionClients(context.Background(), server); rows[0].State != "unknown" || rows[1].State != "disabled" {
				t.Fatal(rows)
			}
			r.fail = false
			if rows = s.sessionClients(context.Background(), server); rows[0].State != tc.state {
				t.Fatal("retry", rows)
			}
			server.Enabled = false
			r.calls = nil
			for _, row := range s.sessionClients(context.Background(), server) {
				if row.State != "server_disabled" {
					t.Fatal(row)
				}
			}
			if len(r.calls) != 0 {
				t.Fatal("queried disabled server")
			}
		})
	}
}
