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
