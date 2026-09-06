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
		{
			`-A NETOS-POLICY -s 10.60.1.0/24 -m comment --comment "канал сегмента" -j MARK --set-mark 0x1001`,
			`-A NETOS-POLICY -s 10.60.1.0/24 -m comment --comment "канал сегмента" -j MARK --set-xmark 0x1001/0xffffffff`,
		},
		{
			`-A PREROUTING -j CONNMARK --restore-mark`,
			`-A PREROUTING -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff`,
		},
		{
			`-A NETOS-POLICY -m mark --mark 0x1001 -j CONNMARK --save-mark`,
			`-A NETOS-POLICY -m mark --mark 0x1001 -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff`,
		},
		{
			`-A PREROUTING -m mark --mark 0 -j NETOS-POLICY`,
			`-A PREROUTING -m mark --mark 0x0 -j NETOS-POLICY`,
		},
		{
			`-A FORWARD -s 10.60.1.130 -d 198.19.0.1 -p tcp -m multiport --dports 8080 -m time --timestart 12:00 --timestop 12:01 -m comment --comment "Full deny HTTP" -j REJECT --reject-with icmp-port-unreachable`,
			`-A FORWARD -s 10.60.1.130/32 -d 198.19.0.1/32 -p tcp -m multiport --dports 8080 -m time --timestart 12:00:00 --timestop 12:01:00 --datestop 2038-01-19T03:14:07 -m comment --comment "Full deny HTTP" -j REJECT --reject-with icmp-port-unreachable`,
		},
		{
			`-A NETOS-MULTIWAN -m statistic --mode random --probability 0.250000 -j MARK --set-mark 0x3001`,
			`-A NETOS-MULTIWAN -m statistic --mode random --probability 0.25000000009 -j MARK --set-xmark 0x3001/0xffffffff`,
		},
	}
	for i, c := range cases {
		if got, want := canonicalRule(c[0]), canonicalRule(c[1]); got != want {
			t.Errorf("case %d:\n generated: %s\n live:      %s", i, got, want)
		}
	}
}
