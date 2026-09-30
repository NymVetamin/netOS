package services

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// This native check runs only on a Linux QA host with dnsmasq and dig.
func TestIntegrationDnsmasqReverseOutsideNarrowLAN(t *testing.T) {
	if os.Getenv("NETOS_DNSMASQ_INTEGRATION") != "1" {
		t.Skip("requires native dnsmasq and dig")
	}
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	var forwarded atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			forwarded.Add(1)
			if answer := ptrMarkerReply(buf[:n]); answer != nil {
				_, _ = upstream.WriteTo(answer, peer)
			}
		}
	}()
	port := upstream.LocalAddr().(*net.UDPAddr).Port
	cfg := config.Default()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "dnsmasq", 15353
	cfg.DNS.LocalDomain = "lan"
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lo"}}
	cfg.Networks = []config.Network{{ID: "lan", Enabled: true, Interface: "lan", RouterAddress: "192.0.2.1/25"}}
	lines := strings.Split(NewDnsmasq(nil).Render(cfg), "\n")
	var kept []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "server=") {
			kept = append(kept, line)
		}
	}
	conf := filepath.Join(t.TempDir(), "dnsmasq.conf")
	kept = append(kept, fmt.Sprintf("server=127.0.0.1#%d", port))
	if err := os.WriteFile(conf, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "dnsmasq", "--no-daemon", "--conf-file="+conf)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	dig := func(ip string) string {
		t.Helper()
		out, err := exec.Command("dig", "@127.0.0.1", "-p", "15353", "-x", ip, "+time=2", "+tries=1", "+short").CombinedOutput()
		if err != nil {
			t.Fatalf("dig %s: %v: %s", ip, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	var outside string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		out, _ := exec.Command("dig", "@127.0.0.1", "-p", "15353", "-x", "192.0.2.200", "+time=1", "+tries=1", "+short").CombinedOutput()
		outside = strings.TrimSpace(string(out))
		if outside == "outside-qa.example." {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if outside != "outside-qa.example." {
		t.Fatalf("PTR outside /25 was not forwarded: %q", outside)
	}
	forwardedBeforeInside := forwarded.Load()
	if got := dig("192.0.2.47"); got != "" {
		t.Fatalf("unknown PTR inside /25 escaped local zone: %q", got)
	}
	if got := forwarded.Load(); got != forwardedBeforeInside {
		t.Fatalf("inside PTR was forwarded upstream: %d -> %d", forwardedBeforeInside, got)
	}
}

func ptrMarkerReply(query []byte) []byte {
	if len(query) < 17 {
		return nil
	}
	end := 12
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	if end+5 > len(query) {
		return nil
	}
	question := query[12 : end+5]
	name := []byte{10}
	name = append(name, []byte("outside-qa")...)
	name = append(name, 7)
	name = append(name, []byte("example")...)
	name = append(name, 0)
	reply := make([]byte, 12)
	copy(reply[:2], query[:2])
	binary.BigEndian.PutUint16(reply[2:4], 0x8180)
	binary.BigEndian.PutUint16(reply[4:6], 1)
	binary.BigEndian.PutUint16(reply[6:8], 1)
	reply = append(reply, question...)
	reply = append(reply, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60)
	reply = append(reply, 0, byte(len(name)))
	reply = append(reply, name...)
	return reply
}
