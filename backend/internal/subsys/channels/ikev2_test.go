package channels

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIKEv2ClientRendersIsolatedXFRMAndEAP(t *testing.T) {
	ch := config.Channel{Index: 3, Name: "office", Type: "ikev2"}
	ike := config.IKEv2ChannelConfig{Server: "vpn.example.com", ServerIdentity: "vpn.example.com", Username: "alice", Password: "secret-password"}
	conf := string(renderIKEv2Client(ch, ike))
	for _, want := range []string{"remote_addrs = vpn.example.com", "auth = eap-mschapv2", "if_id_in = 60003", "if_id_out = 60003", "vips = 0.0.0.0"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in client config", want)
		}
	}
	if strings.Contains(conf, ike.Password) {
		t.Fatal("plaintext EAP password in strongSwan config")
	}
	daemon := string(renderIKEv2ClientDaemon(ch))
	if !strings.Contains(daemon, "port = 0") || !strings.Contains(daemon, "install_virtual_ip_on = xfrm-ch3") || !strings.Contains(daemon, "install_routes = no") {
		t.Fatal("daemon isolation or route ownership missing")
	}
	if !strings.Contains(string(renderIKEv2ClientUnit(ch, ikev2ClientPaths{})), "--initiate --child netos-ch3") {
		t.Fatal("client unit does not initiate connection")
	}
}
