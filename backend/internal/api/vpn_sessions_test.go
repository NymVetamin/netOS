package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
)

func TestVPNSessionParsers(t *testing.T) {
	ike := `list-sa event {netos-srv2 {uniqueid=1 state=ESTABLISHED remote-id=wrong remote-eap-id=alice remote-host=192.0.2.7 remote-port=4500 child-sas {child-1 {state=INSTALLED bytes-in=123 bytes-out=456}}}} list-sas reply {}`
	for _, tc := range []struct {
		name, raw, key, endpoint string
		rx                       uint64
		parse                    func(string) (map[string]vpnClientStatus, bool)
	}{
		{"ocserv", `[{"Username":"alice","State":"connected","Remote IP":"192.0.2.7","RX":"123","TX":"456","Full session":"must-not-leak"}]`, "alice", "192.0.2.7", 123, ocservSessions},
		{"ikev2", ike, "alice", "192.0.2.7:4500", 123, func(raw string) (map[string]vpnClientStatus, bool) { return ikev2Sessions(raw, "netos-srv2") }},
		{"l2tp", `[{"ifname":"ppp-srv2","flags":["POINTOPOINT","UP"],"addr_info":[{"family":"inet","local":"10.9.0.1","address":"10.9.0.2","prefixlen":32}],"stats64":{"rx":{"bytes":123},"tx":{"bytes":456}}}]`, "10.9.0.2", "", 123, func(raw string) (map[string]vpnClientStatus, bool) { return pppSessions(raw, "ppp-srv2") }},
		{"xray", `{"users":[{"email":"srv/phone","ips":[{"ip":"192.0.2.7","lastSeen":1234}],"traffic":{"uplink":123,"downlink":456}}]}`, "srv/phone", "192.0.2.7", 123, xraySessions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, ok := tc.parse(tc.raw)
			if !ok || len(rows) != 1 || rows[tc.key].State != "online" || rows[tc.key].Endpoint != tc.endpoint || rows[tc.key].Received != tc.rx || rows[tc.key].Sent != 456 || !rows[tc.key].TrafficKnown {
				t.Fatalf("bad sessions: %+v %v", rows, ok)
			}
			for _, invalid := range []string{"", "unavailable", tc.raw[:len(tc.raw)-1]} {
				if _, ok := tc.parse(invalid); ok {
					t.Fatalf("accepted malformed output %q", invalid)
				}
			}
		})
	}
	if rows, ok := ocservSessions(`[{"Username":"alice","State":"authenticating"}]`); !ok || len(rows) != 0 {
		t.Fatal("unauthenticated ocserv user online")
	}
	for _, raw := range []string{strings.ReplaceAll(ike, "ESTABLISHED", "CONNECTING"), strings.ReplaceAll(ike, "INSTALLED", "REKEYING"), strings.ReplaceAll(ike, "netos-srv2", "netos-srv3")} {
		if rows, ok := ikev2Sessions(raw, "netos-srv2"); !ok || len(rows) != 0 {
			t.Fatal("wrong or incomplete IKE SA online")
		}
	}
	if rows, ok := ikev2Sessions(strings.ReplaceAll(strings.ReplaceAll(ike, "remote-id=wrong", "remote-id=alice"), "remote-eap-id=alice", ""), "netos-srv2"); !ok || rows["alice"].State != "online" {
		t.Fatal("equal IKE/EAP identity omitted by strongSwan not recognized")
	}
	for _, raw := range []string{`{}`, `{"users":[]}`} {
		if rows, ok := xraySessions(raw); !ok || len(rows) != 0 {
			t.Fatal("empty Xray response rejected")
		}
	}
	if rows, ok := xraySessions(`{"users":[{"email":"alice","ips":[{"ip":"192.0.2.7"}],"traffic":{"uplink":"123"}}]}`); !ok || rows["alice"].Sent != 0 || rows["alice"].Received != 123 {
		t.Fatal("omitted zero protobuf counter rejected")
	}
	for _, raw := range []string{`{"error":"no service"}`, `null`, `{"users":[{"email":"a","ips":[{"ip":"bad"}]}]}`} {
		if _, ok := xraySessions(raw); ok {
			t.Fatal("invalid Xray response accepted")
		}
	}
	if rows, ok := ocservSessions(`[{"Username":"alice","State":"connected","Remote IP":"192.0.2.1","RX":"1","TX":"2"},{"Username":"alice","State":"connected","Remote IP":"192.0.2.2","RX":"3","TX":"4"}]`); !ok || rows["alice"].Received != 4 || rows["alice"].Sent != 6 || rows["alice"].Endpoint != "192.0.2.1, 192.0.2.2" {
		t.Fatal("multiple sessions lost")
	}
}

type sessionRunner struct {
	out   string
	fail  bool
	calls []string
}

func (r *sessionRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.fail {
		return "", errors.New("unavailable")
	}
	return r.out, nil
}
func (r *sessionRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestVPNStatusIdentityFailureAndCache(t *testing.T) {
	runner := &sessionRunner{out: `{"users":[{"email":"srv/phone","ips":[{"ip":"192.0.2.7"}],"traffic":{"uplink":123}}]}`}
	s := &Server{Collector: &runtime.Collector{Runner: runner}}
	server := config.VPNServer{ID: "srv", Type: "xray", Index: 2, Enabled: true, Config: map[string]any{"protocol": "reality"}, Peers: []config.VPNPeer{{ID: "phone", Enabled: true}, {ID: "other", Enabled: true}, {ID: "disabled"}}}
	rows := s.vpnClients(context.Background(), server)
	if rows[0].State != "online" || rows[0].LastSeen == 0 || rows[1].State != "offline" || rows[2].State != "disabled" {
		t.Fatalf("bad states %+v", rows)
	}
	if !strings.Contains(runner.calls[0], "--server=unix:///run/netos-xray-srv2/stats.sock") || strings.Contains(runner.calls[0], "-reset") {
		t.Fatal("wrong Xray command")
	}
	rows[0].State = "corrupted"
	if s.vpnClients(context.Background(), server)[0].State != "online" || len(runner.calls) != 1 {
		t.Fatal("cache alias or duplicate query")
	}
	last := rows[0].LastSeen
	s.vpnStatus[server.ID].at = time.Time{}
	runner.out = `{}`
	rows = s.vpnClients(context.Background(), server)
	if rows[0].State != "offline" || rows[0].LastSeen != last || rows[0].Endpoint != "" {
		t.Fatal("offline transition lost history or kept stale endpoint")
	}
	s.vpnStatus[server.ID].at = time.Time{}
	runner.fail = true
	if rows = s.vpnClients(context.Background(), server); rows[0].State != "unknown" || rows[0].LastSeen != last {
		t.Fatal("failed query presented as offline")
	}
	server.Enabled = false
	if rows = s.vpnClients(context.Background(), server); rows[0].State != "server_disabled" || rows[0].LastSeen != 0 {
		t.Fatal("configuration change reused telemetry")
	}
	runner.fail = false
	server.Enabled = true
	server.Config["protocol"] = "socks"
	server.Peers[0].Credentials = map[string]string{"username": "alice"}
	runner.out = `{"users":[{"email":"alice","ips":[{"ip":"192.0.2.8"}]}]}`
	if s.vpnClients(context.Background(), server)[0].State != "online" {
		t.Fatal("SOCKS username not mapped")
	}
}

func TestOpenConnectCertificateIdentityIsScopedToServerSocket(t *testing.T) {
	runner := &sessionRunner{out: `[{"Username":"netos-phone","State":"connected","Remote IP":"192.0.2.9"},{"Username":"other-user","State":"connected","Remote IP":"192.0.2.10"}]`}
	s := &Server{Collector: &runtime.Collector{Runner: runner}}
	server := config.VPNServer{ID: "oc", Index: 7, Type: "ocserv", Enabled: true, Config: map[string]any{"auth_mode": "certificate"}, Peers: []config.VPNPeer{{ID: "phone", Enabled: true, Credentials: map[string]string{"username": "unused"}}, {ID: "other", Enabled: true}}}
	rows := s.sessionClients(context.Background(), server)
	if rows[0].State != "online" || rows[0].Endpoint != "192.0.2.9" || rows[1].State != "offline" || !strings.Contains(runner.calls[0], "/run/netos-ocserv-srv7/occtl.socket") {
		t.Fatal("certificate CN or server identity incorrectly matched", rows)
	}
}

func TestVPNReadersShareMonitorSnapshot(t *testing.T) {
	runner := &sessionRunner{out: `{}`}
	s := &Server{Collector: &runtime.Collector{Runner: runner}}
	server := config.VPNServer{ID: "srv", Type: "xray", Enabled: true}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); s.vpnClients(context.Background(), server) }()
	}
	wg.Wait()
	if len(runner.calls) != 1 {
		t.Fatalf("cold reads spawned %d commands", len(runner.calls))
	}
	cache := s.vpnStatus[server.ID]
	cache.at = time.Now().Add(-4 * time.Second)
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); s.vpnClients(context.Background(), server) }()
	}
	wg.Wait()
	if len(runner.calls) != 1 {
		t.Fatal("readers refreshed a warm monitor snapshot")
	}
	cycle := time.Now()
	_, at := s.vpnClientSnapshot(context.Background(), server, cycle)
	if len(runner.calls) != 2 || at.Before(cycle) {
		t.Fatal("monitor did not refresh")
	}
	s.vpnClientSnapshot(context.Background(), server, cycle)
	if len(runner.calls) != 2 {
		t.Fatal("same cycle duplicated a completed sample")
	}
	server.Peers = []config.VPNPeer{{ID: "new", Enabled: true}}
	if rows := s.vpnClients(context.Background(), server); len(rows) != 1 || rows[0].ID != "new" || len(runner.calls) != 3 {
		t.Fatal("config change did not invalidate")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cache = s.vpnStatus[server.ID]
	previous := cache.at
	s.vpnClientSnapshot(ctx, server, time.Now())
	if !cache.at.Equal(previous) {
		t.Fatal("cancelled caller poisoned shared cache")
	}
}
