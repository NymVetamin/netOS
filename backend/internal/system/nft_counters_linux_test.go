//go:build linux

package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNFTSetCountersKernel(t *testing.T) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace")
	}
	run := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %s %v", out, err)
		}
	}
	run(`add table inet qa_counters
add set inet qa_counters up4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet qa_counters down4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet qa_counters up6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet qa_counters down6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; counter; }
add element inet qa_counters up4 { 192.0.2.1 counter packets 7 bytes 12345 }
add element inet qa_counters down6 { 2001:db8::1 counter packets 7 bytes 98765 }
`)
	e := NewExec()
	e.Timeout = 2 * time.Second
	for i := 0; i < 3; i++ {
		sets, err := e.NFTSetCounters(context.Background(), "qa_counters")
		if err != nil {
			t.Fatal(err)
		}
		if len(sets) != 4 || sets["up4"]["192.0.2.1"] != 12345 || sets["down6"]["2001:db8::1"] != 98765 || len(sets["down4"]) != 0 {
			t.Fatalf("unexpected: %#v", sets)
		}
	}
	run("delete element inet qa_counters up4 { 192.0.2.1 }")
	sets, err := e.NFTSetCounters(context.Background(), "qa_counters")
	if err != nil || len(sets["up4"]) != 0 {
		t.Fatalf("deleted element: %v %v", sets, err)
	}
	var many strings.Builder
	for i := 1; i <= 1024; i++ {
		fmt.Fprintf(&many, "add element inet qa_counters up6 { 2001:db8:1::%x counter packets 1 bytes %d }\n", i, i*100)
	}
	run(many.String())
	sets, err = e.NFTSetCounters(context.Background(), "qa_counters")
	if err != nil || len(sets["up6"]) != 1024 || sets["up6"]["2001:db8:1::400"] != 102400 {
		t.Fatalf("multipart dump: count=%d err=%v", len(sets["up6"]), err)
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("lo: %s %v", out, err)
	}
	run("add chain inet qa_counters traffic { type filter hook output priority 10; policy accept; }\nadd rule inet qa_counters traffic ip protocol icmp update @up4 { ip saddr counter }")
	if out, err := exec.Command("ping", "-c", "3", "-i", "0.01", "-s", "56", "127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("ping: %s %v", out, err)
	}
	sets, err = e.NFTSetCounters(context.Background(), "qa_counters")
	if err != nil || sets["up4"]["127.0.0.1"] != 504 {
		t.Fatalf("real packet bytes: %v %v", sets["up4"], err)
	}
	run("delete table inet qa_counters")
	if _, err := e.NFTSetCounters(context.Background(), "qa_counters"); err == nil {
		t.Fatal("missing table accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.NFTSetCounters(ctx, "qa_counters"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestNFTCounterMalformed(t *testing.T) {
	for _, data := range [][]byte{{1}, {3, 0, 1, 0}, {9, 0, 1, 0, 0, 0, 0, 0}} {
		if _, err := nftAttrs(data); err == nil {
			t.Fatalf("accepted malformed attribute %x", data)
		}
	}
	badKey := nftAttr(3, nftAttr(1, nftAttr(1, nftAttr(1, []byte{1, 2, 3}))))
	if err := parseNFTCounters(badKey, map[string]uint64{}); err == nil {
		t.Fatal("accepted malformed IP key")
	}
}
