package vpnservers

import (
	"bytes"
	"encoding/json"
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestIKEv2AuthSplitRoutesRemainPerServerAndFresh(t *testing.T) {
	_, first := ikev2TestConfig()
	_, second := ikev2TestConfig()
	first.Config["split_routes"] = []string{"10.0.0.0/8", "10.0.0.0/8"}
	first.Config["dns"] = []string{"10.40.0.1", "1.1.1.1", "1.1.1.1"}
	second.Index = 3
	second.Config["split_routes"] = []string{"192.168.0.0/16"}
	second.Config["dns"] = []string{"9.9.9.9"}
	first.Peers = []config.VPNPeer{
		{Enabled: true, Address: "10.40.0.2", Credentials: map[string]string{"username": "a", "password": "test"}},
		{Enabled: false, Address: "invalid", Credentials: map[string]string{"username": "disabled"}},
		{Enabled: true, Address: "10.40.0.3", Credentials: map[string]string{"username": "b", "password": "test"}},
	}
	second.Peers = []config.VPNPeer{{Enabled: true, Address: "10.50.0.2", Credentials: map[string]string{"username": "c", "password": "test"}}}
	servers := []config.VPNServer{first, second}
	before, _ := json.Marshal(servers)
	check := func(firstWant string) {
		t.Helper()
		data, err := renderIKEv2AuthUsers(servers)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), `CVPN3000-IPSec-Split-Tunnel-List = "`+firstWant+`"`) != 2 {
			t.Fatalf("first server routes lost: %s", data)
		}
		if strings.Count(string(data), `CVPN3000-IPSec-Split-Tunnel-List = "192.168.0.0/16,9.9.9.9/32"`) != 1 {
			t.Fatalf("routes leaked between servers: %s", data)
		}
	}
	check("10.0.0.0/8,10.0.0.0/8,1.1.1.1/32,1.1.1.1/32")
	after, _ := json.Marshal(servers)
	if !bytes.Equal(before, after) {
		t.Fatal("input mutated")
	}
	first.Config["dns"] = []string{"bad"}
	if _, err := renderIKEv2AuthUsers(servers); err == nil {
		t.Fatal("invalid DNS accepted")
	}
	first.Config["dns"] = []string{"8.8.8.8"}
	check("10.0.0.0/8,10.0.0.0/8,8.8.8.8/32")
}
