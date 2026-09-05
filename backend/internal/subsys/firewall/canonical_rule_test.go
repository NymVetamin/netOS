package firewall

import "testing"

func TestCanonicalRuleMatchesNftRendering(t *testing.T) {
	cases := [][2]string{
		{
			`-A FORWARD -p tcp -s 192.0.2.50 -d 198.18.34.1 -m multiport --dports 8001 -m comment --comment "r934 filter" -j LOG --log-prefix "netos r934 filter: " --log-level 4`,
			`-A FORWARD -s 192.0.2.50/32 -d 198.18.34.1/32 -p tcp -m multiport --dports 8001 -m comment --comment "r934 filter" -j LOG --log-prefix "netos r934 filter: "`,
		},
		{
			`-A WAN-FWD -d 192.0.2.50 -p udp --dport 8002 -m conntrack --ctstate DNAT -j ACCEPT`,
			`-A WAN-FWD -d 192.0.2.50/32 -p udp -m udp --dport 8002 -m conntrack --ctstate DNAT -j ACCEPT`,
		},
		{
			`-A PREROUTING -s 192.0.2.0/24 ! -d 192.0.2.1/32 -p udp --dport 53 -j DNAT --to-destination 192.0.2.1:53`,
			`-A PREROUTING ! -d 192.0.2.1/32 -s 192.0.2.0/24 -p udp -m udp --dport 53 -j DNAT --to-destination 192.0.2.1:53`,
		},
	}
	for i, c := range cases {
		if got, want := canonicalRule(c[0]), canonicalRule(c[1]); got != want {
			t.Errorf("case %d:\n generated: %s\n live:      %s", i, got, want)
		}
	}
}
