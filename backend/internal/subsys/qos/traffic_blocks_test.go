package qos

import (
	"fmt"
	"strings"
	"testing"
)

func legacyBlockHasTokens(output, boundary string, tokens ...string) bool {
	var blocks []string
	var current strings.Builder
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, boundary) && current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
		if trimmed != "" {
			current.WriteByte(' ')
			current.WriteString(trimmed)
		}
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}
	for _, block := range blocks {
		fields := trafficFields(block)
		matched := true
		for _, token := range tokens {
			if pair := strings.SplitN(token, "=", 2); len(pair) == 2 {
				found := false
				for i := 0; i+1 < len(fields); i++ {
					if normalizeTrafficToken(fields[i]) == normalizeTrafficToken(pair[0]) && normalizeTrafficToken(fields[i+1]) == normalizeTrafficToken(pair[1]) {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
				continue
			}
			want := normalizeTrafficToken(token)
			found := false
			for _, field := range fields {
				if normalizeTrafficToken(field) == want {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func TestTrafficBlocksKeepConditionsInSameBlock(t *testing.T) {
	blocks := parseTrafficBlocks("filter pref 100 src_mac aa:bb rate 1Mbit mtu 64Kb\nfilter pref 101 src_mac aa:cc rate 2Mbit mtu 2Kb", "filter ")
	for _, query := range [][]string{
		{"pref=100", "src_mac=aa:bb", "rate=1000000bit", "mtu=64kb"},
		{"pref=101", "src_mac=aa:cc", "rate=2000kbit", "mtu=2kb"},
	} {
		if !blocks.hasTokens(query...) {
			t.Fatalf("missing matching filter: %q", query)
		}
	}
	for _, query := range [][]string{
		{"pref=100", "src_mac=aa:cc"},
		{"src_mac=aa:bb", "rate=2000kbit"},
		{"pref=101", "mtu=64kb"},
		{"rate=64kb"},
	} {
		if blocks.hasTokens(query...) {
			t.Fatalf("accepted mismatched filter: %q", query)
		}
	}
}

func TestTrafficBlocksEquivalent(t *testing.T) {
	outputs := []string{"", " \n\t", "!!!", "preamble\nfilter pref 100 flower\n src_mac aa:bb\n police rate 1Mbit burst 64Kb mtu 64Kb", "filter pref 100 src_mac aa:bb\nfilter police rate 1000Kbit mtu 64Kb", "class htb 1:10 rate 1Mbit ceil 2Mbit\nclass htb 1:11 rate 2Mbit ceil 1Mbit", "FILTER pref 100 pref 100\r\n src_mac AA:BB rate 1000000bit mtu 64Kb", "filter pref 100\nfilter pref 100 src_mac aa:bb rate 1Mbit\nfilter pref 101 src_mac aa:cc rate 2Mbit"}
	queries := [][]string{nil, {"!!!"}, {"pref", "100"}, {"pref=100", "src_mac=aa:bb", "rate=1000kbit", "mtu=64kb"}, {"src_mac", "aa:bb", "police", "rate=1mbit"}, {"class", "htb", "1:10", "rate=2000kbit", "ceil=1000kbit"}, {"class", "htb", "1:10", "rate=1000kbit", "ceil=2000kbit"}, {""}, {"="}, {"rate=1mbit=extra"}, {"pref=100", "pref=100"}, {"SRC_MAC=AA:BB"}}
	for _, boundary := range []string{"filter ", "class ", "FILTER ", ""} {
		for _, output := range outputs {
			blocks := parseTrafficBlocks(output, boundary)
			for _, query := range queries {
				got, want := blocks.hasTokens(query...), legacyBlockHasTokens(output, boundary, query...)
				if got != want {
					t.Fatalf("output=%q boundary=%q query=%q got %v want %v", output, boundary, query, got, want)
				}
			}
		}
	}
}

func FuzzTrafficBlocksEquivalent(f *testing.F) {
	f.Add("filter pref 100\n src_mac aa:bb rate 1Mbit", "filter ", "pref=100", "rate=1000kbit")
	f.Add("!!!", "class ", "", "=")
	f.Fuzz(func(t *testing.T, output, boundary, first, second string) {
		blocks := parseTrafficBlocks(output, boundary)
		for _, query := range [][]string{nil, {first}, {first, second}} {
			if got, want := blocks.hasTokens(query...), legacyBlockHasTokens(output, boundary, query...); got != want {
				t.Fatalf("query=%q got %v want %v", query, got, want)
			}
		}
	})
}

func BenchmarkTrafficBlocks(b *testing.B) {
	for _, n := range []int{1, 50, 100, 200} {
		var out strings.Builder
		queries := make([][]string, n)
		for i := 0; i < n; i++ {
			mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
			fmt.Fprintf(&out, "filter protocol all pref %d flower\n  src_mac %s\n  police rate 1000Kbit burst 64Kb mtu 64Kb\n", 100+i, mac)
			queries[i] = []string{"pref", fmt.Sprint(100 + i), "src_mac", mac, "police", "rate", "1000kbit", "mtu=64kb"}
		}
		output := out.String()
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.Run("legacy", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for _, q := range queries {
						if !legacyBlockHasTokens(output, "filter ", q...) {
							b.Fatal("missing")
						}
					}
				}
			})
			b.Run("indexed", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					blocks := parseTrafficBlocks(output, "filter ")
					for _, q := range queries {
						if !blocks.hasTokens(q...) {
							b.Fatal("missing")
						}
					}
				}
			})
		})
	}
}
