package vpnservers

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestL2TPRouterDNSFollowsSubnetAndPreservesManualList(t *testing.T) {
	server := config.VPNServer{Type: "l2tp", Subnet: "10.99.0.1/24", Config: map[string]any{"use_router_dns": true, "dns": []string{"9.9.9.9"}}}
	for _, subnet := range []string{"10.99.0.1/24", "10.98.0.17/24"} {
		server.Subnet = subnet
		cfg, err := server.L2TPConfig()
		if err != nil {
			t.Fatal(err)
		}
		ppp := renderL2TPPPP(server, cfg)
		if !strings.Contains(ppp, "ms-dns "+strings.Split(subnet, "/")[0]+"\n") || strings.Contains(ppp, "ms-dns 9.9.9.9") {
			t.Fatal(ppp)
		}
	}
	server.Config["use_router_dns"] = false
	cfg, _ := server.L2TPConfig()
	if ppp := renderL2TPPPP(server, cfg); !strings.Contains(ppp, "ms-dns 9.9.9.9\n") {
		t.Fatal(ppp)
	}
	delete(server.Config, "use_router_dns")
	server.Config["dns"] = []string{}
	cfg, _ = server.L2TPConfig()
	if strings.Contains(renderL2TPPPP(server, cfg), "ms-dns") {
		t.Fatal("legacy empty DNS changed")
	}
}

func TestIKEv2RouterDNSReachesRadiusAndSplitSelectors(t *testing.T) {
	cfg, server := ikev2TestConfig()
	server.Config["dns"] = []string{"9.9.9.9"}
	server.Config["use_router_dns"] = true
	server.Config["split_routes"] = []string{"192.0.3.0/24"}
	for _, subnet := range []string{"10.40.0.1/24", "10.41.0.7/24"} {
		server.Subnet = subnet
		ip := strings.Split(subnet, "/")[0]
		swan, err := RenderIKEv2([]config.VPNServer{server}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		users, err := renderIKEv2AuthUsers([]config.VPNServer{server})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(swan), "local_ts = 192.0.3.0/24, "+ip+"/32") || !strings.Contains(string(users), "MS-Primary-DNS-Server += "+ip) || !strings.Contains(string(users), "192.0.3.0/24,"+ip+"/32") || strings.Contains(string(users), "9.9.9.9") {
			t.Fatalf("DNS/route lost: %s\n%s", swan, users)
		}
	}
	server.Config["use_router_dns"] = false
	users, err := renderIKEv2AuthUsers([]config.VPNServer{server})
	if err != nil || !strings.Contains(string(users), "MS-Primary-DNS-Server += 9.9.9.9") {
		t.Fatalf("manual DNS lost: %s %v", users, err)
	}
}
