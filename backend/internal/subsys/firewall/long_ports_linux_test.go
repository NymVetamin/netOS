package firewall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Run in a fresh unshare -n namespace for each iptables implementation.
func TestIntegrationLongPortPackets(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and NETOS_INTEGRATION=1")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initErr != nil || self == initNS {
		t.Fatal("requires an isolated network namespace")
	}
	ipt := os.Getenv("NETOS_TEST_IPTABLES")
	if ipt == "" {
		ipt = "iptables"
	}
	run := func(input, cmd string, args ...string) string {
		t.Helper()
		c := exec.Command(cmd, args...)
		c.Stdin = strings.NewReader(input)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", cmd, args, err, out)
		}
		return string(out)
	}
	run("", "ip", "link", "set", "lo", "up")
	ports := func(base int) string {
		var list []string
		for i := 0; i < 15; i++ {
			list = append(list, strconv.Itoa(base+i))
		}
		return strings.Join(list, ",") + fmt.Sprintf(",%d-%d,%d-%d", base, base+2, base+20, base+20)
	}
	var b builder
	b.line("*filter")
	for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		b.line(":%s ACCEPT [0:0]", chain)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		b.emitRule("OUTPUT", config.FirewallRule{ID: protocol, Name: protocol, Action: "continue", Protocol: protocol, SrcPort: ports(21000), DstPort: ports(31000), Log: true}, "")
	}
	b.line("-A OUTPUT -p udp -m comment --comment after -j ACCEPT")
	b.line("COMMIT")
	b.line("*mangle")
	for _, chain := range []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"} {
		b.line(":%s ACCEPT [0:0]", chain)
	}
	cfg := config.Default()
	cfg.Policies = []config.Policy{
		{ID: "first", Name: "first", Enabled: true, Priority: 10, Channel: "direct", Protocol: "udp", DstPort: ports(31000)},
		{ID: "fallback", Name: "fallback", Enabled: true, Priority: 20, Channel: "direct", Protocol: "udp"},
	}
	b.channelPolicies(cfg)
	b.line("COMMIT")
	for pass := 0; pass < 2; pass++ {
		run(b.String(), ipt+"-restore")
		for _, p := range [][2]int{{21000, 31000}, {21020, 31020}, {21030, 31020}, {21020, 31030}} {
			dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p[1]}
			receiver, err := net.ListenUDP("udp4", dst)
			if err != nil {
				t.Fatal(err)
			}
			sender, err := net.DialUDP("udp4", &net.UDPAddr{IP: dst.IP, Port: p[0]}, dst)
			if err != nil {
				receiver.Close()
				t.Fatal(err)
			}
			_, err = sender.Write([]byte{1})
			sender.Close()
			if err != nil {
				receiver.Close()
				t.Fatal(err)
			}
			receiver.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err = receiver.ReadFromUDP(make([]byte, 1))
			receiver.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		// A closed loopback port answers one SYN immediately with a reset.
		dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21000 + pass}}
		conn, err := dialer.Dial("tcp4", "127.0.0.1:31020")
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("expected TCP reset: %v", err)
		}
		saved := run("", ipt+"-save")
		if !rulesetMatches(saved, b.String()) {
			t.Errorf("pass %d canonical mismatch:\nlive:\n%s\nexpected:\n%s", pass, saved, b.String())
		}
		saved = run("", ipt+"-save", "-c")
		for marker, want := range map[string]int{"--log-prefix \"netos udp: ": 2, "--log-prefix \"netos tcp: ": 1, "--comment udp": 2, "--comment tcp": 1, "--comment after": 4, "--comment first": 3, "--comment fallback": 1} {
			total := 0
			for line := range strings.SplitSeq(saved, "\n") {
				if strings.Contains(line, " -j NETOS-PORT-") {
					continue
				}
				if !strings.Contains(strings.ReplaceAll(line, "--comment \"", "--comment "), marker) {
					continue
				}
				var n int
				if _, err := fmt.Sscanf(line, "[%d:", &n); err != nil {
					t.Fatalf("bad counter %q: %v", line, err)
				}
				total += n
			}
			if total != want {
				t.Errorf("pass %d %s counted %d, want %d:\n%s", pass, marker, total, want, saved)
			}
		}
	}
}
