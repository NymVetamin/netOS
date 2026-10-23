package vpnservers

import (
	"context"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestWireGuardExportSettingsDoNotPlanServerChange(t *testing.T) {
	s, runner := newTestSubsystem(t)
	old := serverConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := serverConfig()
	next.VPNServers[0].Peers[0].WireGuardProfile = &config.WireGuardClientProfile{DNS: []string{"192.0.2.53"}, AllowedIPs: []string{"198.51.100.0/24"}}
	next.VPNServers[0].Config["public_endpoint"] = "vpn.example:51820"
	next.VPNServers[0].Config["client_dns"] = []string{"192.0.2.54"}
	next.VPNServers[0].Config["client_allowed_ips"] = []string{"192.0.2.0/24"}
	before, _ := RenderWireGuard(old.VPNServers[0])
	after, _ := RenderWireGuard(next.VPNServers[0])
	if before != after {
		t.Fatal("export settings changed server config")
	}
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 0 {
		t.Fatalf("export settings plan: %v %v", actions, err)
	}
	if !reflect.DeepEqual(old, serverConfig()) || next.VPNServers[0].Peers[0].WireGuardProfile == nil {
		t.Fatal("comparison mutated configuration")
	}
	next.VPNServers[0].Port++
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("mixed port change lost protection: %v %v", actions, err)
	}
	next.VPNServers[0].Port--
	runner.up = false
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || actions[0].Target != "живое состояние VPN-серверов" {
		t.Fatalf("runtime repair lost protection: %v %v", actions, err)
	}
}

func TestWireGuardChannelDoesNotPlanServerRestart(t *testing.T) {
	s, runner := newTestSubsystem(t)
	old := serverConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := serverConfig()
	next.VPNServers[0].DefaultChannel = "alternate"
	next.VPNServers[0].Peers[0].Channel = "peer-channel"
	before, _ := RenderWireGuard(old.VPNServers[0])
	after, _ := RenderWireGuard(next.VPNServers[0])
	if before != after {
		t.Fatal("channel changed WireGuard runtime configuration")
	}
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 0 {
		t.Fatalf("routing-only server plan: %v %v", actions, err)
	}
	if !reflect.DeepEqual(old, serverConfig()) || next.VPNServers[0].Peers[0].Channel != "peer-channel" {
		t.Fatal("comparison mutated configuration")
	}
	next.VPNServers[0].Port++
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("mixed port change: %v %v", actions, err)
	}
	next.VPNServers[0].Port--
	runner.up = false
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("runtime repair: %v %v", actions, err)
	}
}

func TestDisabledWireGuardPeerDoesNotPlanServerChange(t *testing.T) {
	s, runner := newTestSubsystem(t)
	old := serverConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := serverConfig()
	peer := next.VPNServers[0].Peers[0]
	peer.ID, peer.Name, peer.Address, peer.Enabled = "disabled", "Stored peer", "10.9.0.3", false
	next.VPNServers[0].Peers = append(next.VPNServers[0].Peers, peer)
	for _, pair := range [][2]*config.Config{{old, next}, {next, old}} {
		before, _ := RenderWireGuard(pair[0].VPNServers[0])
		after, _ := RenderWireGuard(pair[1].VPNServers[0])
		if before != after {
			t.Fatal("disabled peer changed runtime configuration")
		}
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("disabled peer plan: %v %v", actions, err)
		}
	}
	if len(next.VPNServers[0].Peers) != 2 {
		t.Fatal("comparison removed stored peer")
	}
	edited := *next
	edited.VPNServers = append([]config.VPNServer(nil), next.VPNServers...)
	edited.VPNServers[0].Peers = append([]config.VPNPeer(nil), next.VPNServers[0].Peers...)
	edited.VPNServers[0].Peers[1].Name = "Edited stored peer"
	edited.VPNServers[0].Peers[1].Address = "10.9.0.5"
	if actions, err := s.Plan(next, &edited); err != nil || len(actions) != 0 {
		t.Fatalf("disabled peer edit: %v %v", actions, err)
	}
	next.VPNServers[0].Peers[1].Enabled = true
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("enable lost confirmation: %v %v", actions, err)
	}
	next.VPNServers[0].Peers[1].Enabled = false
	next.VPNServers[0].Peers[0].Address = "10.9.0.4"
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("active change lost confirmation: %v %v", actions, err)
	}
	next.VPNServers[0].Peers[0].Address = old.VPNServers[0].Peers[0].Address
	runner.up = false
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("repair lost confirmation: %v %v", actions, err)
	}
}
