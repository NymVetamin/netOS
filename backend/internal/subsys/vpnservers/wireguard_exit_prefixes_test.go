package vpnservers

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestWireGuardExitPrefixesExactSet(t *testing.T) {
	random := rand.New(rand.NewSource(1741))
	for trial := 0; trial < 300; trial++ {
		peers := []config.VPNPeer{{Enabled: true, Address: "0.0.0.0"}, {Enabled: true, Address: "255.255.255.255"}}
		for i, size := 0, random.Intn(500)+1; i < size; i++ {
			n := random.Intn(1024)
			peers = append(peers, config.VPNPeer{Enabled: random.Intn(4) != 0, Address: fmt.Sprintf("10.8.%d.%d", n/256, n%256)})
		}
		before := slices.Clone(peers)
		want := map[netip.Addr]bool{}
		for _, peer := range peers {
			if peer.Enabled {
				want[netip.MustParseAddr(peer.Address)] = true
			}
		}
		prefixes := wireGuardExitPrefixes(peers)
		got := map[netip.Addr]bool{}
		for _, prefix := range prefixes {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				t.Fatal("invalid prefix", prefix)
			}
			count := uint64(1) << (32 - prefix.Bits())
			if count > uint64(len(want)) {
				t.Fatal("prefix admits extra addresses", prefix)
			}
			address := prefix.Addr()
			for n := uint64(0); n < count; n++ {
				if got[address] {
					t.Fatal("overlapping prefixes", address)
				}
				got[address] = true
				address = address.Next()
			}
		}
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, peers) {
			t.Fatalf("trial %d: changed allowlist or input", trial)
		}
		random.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		if !slices.Equal(prefixes, wireGuardExitPrefixes(peers)) {
			t.Fatal("input order changed the union")
		}
	}
}

func TestWireGuardExitGuardCompactionAndFreshness(t *testing.T) {
	server := config.VPNServer{Index: 7, Type: "wireguard", Enabled: true, Peers: []config.VPNPeer{
		{Address: "10.8.0.3", Enabled: true},
		{Address: "10.8.0.2", Enabled: true, UseAsChannel: true},
		{Address: "10.8.0.2", Enabled: true},
		{Address: "invalid", Enabled: false},
	}}
	want := []string{
		"-A NETOS-WGEXIT7 -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN",
		"-A NETOS-WGEXIT7 -s 10.8.0.2/31 -j RETURN",
		"-A NETOS-WGEXIT7 -j DROP",
	}
	for i := 0; i < 2; i++ {
		chain, rules := WireGuardExitGuard(server)
		if chain != "NETOS-WGEXIT7" || !slices.Equal(rules, want) {
			t.Fatal(chain, rules)
		}
	}
	server.Peers[0].Enabled = false
	_, rules := WireGuardExitGuard(server)
	if !strings.Contains(strings.Join(rules, "\n"), "-s 10.8.0.2/32 -j RETURN") || len(rules) != 3 {
		t.Fatal("disabled address still admitted", rules)
	}
	server.Peers[1].UseAsChannel = false
	if chain, rules := WireGuardExitGuard(server); chain != "" || rules != nil {
		t.Fatal("guard without exit", chain, rules)
	}
}

func TestWireGuardExitPrefixesCompleteBlocks(t *testing.T) {
	for _, count := range []int{2, 256, 2500} {
		peers := make([]config.VPNPeer, count)
		address := netip.MustParseAddr("0.0.0.0")
		for i := range peers {
			peers[i] = config.VPNPeer{Enabled: true, Address: address.String()}
			address = address.Next()
		}
		prefixes := wireGuardExitPrefixes(peers)
		wantCount := 1
		if count == 2500 {
			wantCount = 5
		}
		if len(prefixes) != wantCount {
			t.Fatal(count, prefixes)
		}
		next := netip.MustParseAddr("0.0.0.0")
		for _, prefix := range prefixes {
			if prefix.Addr() != next {
				t.Fatal("gap or overlap", prefix, next)
			}
			size := uint64(1) << (32 - prefix.Bits())
			if size > uint64(count) {
				t.Fatal("prefix exceeds input range", prefix)
			}
			for n := uint64(0); n < size; n++ {
				next = next.Next()
			}
		}
		if next != address {
			t.Fatal("range end changed", next, address)
		}
	}
}

func TestWireGuardExitGuardInvalidAddressPreservesRestoreInput(t *testing.T) {
	for _, invalid := range []string{"", "invalid", "10.8.0.2/24", "::ffff:10.8.0.2", "2001:db8::1", "010.8.0.2"} {
		server := config.VPNServer{Index: 1, Type: "wireguard", Enabled: true, Peers: []config.VPNPeer{
			{Address: "10.8.0.3", Enabled: true, UseAsChannel: true},
			{Address: invalid, Enabled: true},
			{Address: "10.8.0.2", Enabled: true},
		}}
		_, rules := WireGuardExitGuard(server)
		if len(rules) != 5 || rules[1] != "-A NETOS-WGEXIT1 -s 10.8.0.3/32 -j RETURN" ||
			rules[2] != "-A NETOS-WGEXIT1 -s "+invalid+"/32 -j RETURN" || rules[3] != "-A NETOS-WGEXIT1 -s 10.8.0.2/32 -j RETURN" {
			t.Fatal("invalid input silently altered", invalid, rules)
		}
	}
}
