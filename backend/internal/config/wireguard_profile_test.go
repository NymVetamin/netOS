package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWireGuardProfilesArePerClientAndPreserveLegacy(t *testing.T) {
	cfg := validWGServerConfig()
	server := &cfg.VPNServers[0]
	server.Config["client_dns"] = []string{"192.0.2.53"}
	server.Config["client_allowed_ips"] = []string{"192.0.2.0/24"}
	legacy := server.Peers[0]
	profile, err := server.WireGuardProfileFor(legacy)
	if err != nil || !reflect.DeepEqual(profile.DNS, []string{"192.0.2.53"}) || !reflect.DeepEqual(profile.AllowedIPs, []string{"192.0.2.0/24"}) {
		t.Fatal("legacy settings changed")
	}
	custom := legacy
	custom.WireGuardProfile = &WireGuardClientProfile{DNS: []string{}, AllowedIPs: []string{"198.51.100.0/24"}}
	profile, _ = server.WireGuardProfileFor(custom)
	if len(profile.DNS) != 0 || profile.AllowedIPs[0] != "198.51.100.0/24" {
		t.Fatal("explicit empty DNS inherited legacy settings")
	}
	router := legacy
	router.WireGuardProfile = &WireGuardClientProfile{UseRouterDNS: true, AllowedIPs: []string{"0.0.0.0/0"}}
	for _, address := range []string{"10.9.0.1", "10.44.0.254"} {
		server.Subnet = address + "/24"
		profile, _ = server.WireGuardProfileFor(router)
		if len(profile.DNS) != 1 || profile.DNS[0] != address {
			t.Fatal("default DNS did not follow router address")
		}
	}
	server.Peers = []VPNPeer{legacy, custom, router}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored Config
	if err = json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	for i, p := range server.Peers {
		want, _ := server.WireGuardProfileFor(p)
		got, _ := restored.VPNServers[0].WireGuardProfileFor(restored.VPNServers[0].Peers[i])
		if !reflect.DeepEqual(want, got) {
			t.Fatal("profile changed on config round trip")
		}
	}
	delete(server.Config, "client_dns")
	delete(server.Config, "client_allowed_ips")
	profile, _ = server.WireGuardProfileFor(legacy)
	if len(profile.DNS) != 0 || profile.AllowedIPs[0] != "0.0.0.0/0" {
		t.Fatal("legacy empty profile changed")
	}
}

func TestWireGuardClientProfileValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile WireGuardClientProfile
		bad     string
	}{
		{"router", WireGuardClientProfile{UseRouterDNS: true, AllowedIPs: []string{"0.0.0.0/0"}}, ""},
		{"custom", WireGuardClientProfile{DNS: []string{"192.0.2.53", "2001:db8::53"}, AllowedIPs: []string{"198.51.100.0/24", "10.9.0.1/32"}}, ""},
		{"no DNS", WireGuardClientProfile{DNS: []string{}, AllowedIPs: []string{"0.0.0.0/0"}}, ""},
		{"invalid DNS", WireGuardClientProfile{DNS: []string{"bad\nDNS"}, AllowedIPs: []string{"0.0.0.0/0"}}, ".dns[0]"},
		{"no routes", WireGuardClientProfile{AllowedIPs: []string{}}, ".allowed_ips"},
		{"invalid route", WireGuardClientProfile{AllowedIPs: []string{"not-a-subnet"}}, ".allowed_ips[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validWGServerConfig()
			delete(cfg.VPNServers[0].Config, "client_allowed_ips")
			cfg.VPNServers[0].Peers[0].WireGuardProfile = &tc.profile
			result := cfg.Validate()
			if tc.bad == "" {
				if result.HasErrors() {
					t.Fatalf("valid profile rejected: %+v", result.Problems)
				}
				return
			}
			for _, p := range result.Problems {
				if strings.HasSuffix(p.Path, ".wireguard_profile"+tc.bad) {
					return
				}
			}
			t.Fatalf("invalid client field not reported: %+v", result.Problems)
		})
	}
}
