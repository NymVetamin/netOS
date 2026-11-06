package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestPolicyBlockPreservesConditionsAndPriority(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{
		{ID: "deny", Name: "deny", Enabled: true, Priority: 20, Channel: config.InternetBlockChannel, SrcIP: "192.0.2.2", DstIP: "198.51.100.2", Protocol: "tcp", DstPort: "443"},
		{ID: "allow", Name: "allow", Enabled: true, Priority: 10, Channel: "direct", DstIP: "198.51.100.1"},
	}
	render := func() string {
		t.Helper()
		r, e := Build(c)
		if e != nil {
			t.Fatal(e)
		}
		return r.IPv4
	}
	first := render()
	want := `-A NETOS-POLICY -s 192.0.2.2 -p tcp -d 198.51.100.2 -m multiport --dports 443 -m addrtype ! --dst-type LOCAL -m comment --comment "deny" -j DROP`
	if !strings.Contains(first, want) {
		t.Fatal("missing conditional DROP", first)
	}
	if strings.Index(first, `--comment "allow"`) > strings.Index(first, want) {
		t.Fatal("priority lost")
	}
	if render() != first {
		t.Fatal("render is not repeatable")
	}
	c.Policies[0].Enabled = false
	if strings.Contains(render(), want) {
		t.Fatal("disabled block emitted")
	}
	c.Policies[0].Enabled = true
	c.Policies[0].Channel = "direct"
	if strings.Contains(render(), want) {
		t.Fatal("block survived output change")
	}
}
