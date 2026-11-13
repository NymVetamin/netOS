//go:build linux

package api

import (
	"context"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationFirewallLogPage(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized root test machine")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := strconv.Itoa(listener.LocalAddr().(*net.UDPAddr).Port)
	name := "qa-fw-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	cfg := config.Default()
	cfg.Firewall.Rules = []config.FirewallRule{{Name: name, Enabled: true, Zone: "global", Flow: "out", Interface: "lo", Protocol: "udp", DstIP: "127.0.0.1", DstPort: port, Log: true, Action: "continue"}}
	rules, err := firewall.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, candidate := range strings.Split(rules.IPv4, "\n") {
		if strings.HasPrefix(candidate, "-A OUTPUT ") && strings.Contains(candidate, "-j LOG ") && strings.Contains(candidate, name) {
			if line != "" {
				t.Fatal("ambiguous generated fixture")
			}
			line = candidate
		}
	}
	if line == "" {
		t.Fatal("missing generated LOG rule")
	}
	// Only the generated loopback/UDP/destination-port LOG rule is installed.
	// All shell values originate above from fixed ASCII strings and numbers.
	command := func(op string) (string, error) {
		return run.Run(ctx, "/bin/sh", "-c", "iptables -w "+strings.Replace(line, "-A OUTPUT", op, 1))
	}
	if out, err := command("-I OUTPUT 1"); err != nil {
		t.Fatal(out, err)
	}
	t.Cleanup(func() {
		if out, err := command("-D OUTPUT"); err != nil {
			t.Error("cleanup", out, err)
		}
		if _, err := command("-C OUTPUT"); err == nil {
			t.Error("test rule remained")
		}
	})
	from := time.Now().UTC().Add(-time.Second)
	conn, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("firewall-log-page")); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := listener.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "firewall-log-page" {
		t.Fatal("packet delivery", err)
	}
	// Wait for the asynchronous kernel->journald ingestion, then freeze a snapshot.
	var raw string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
			t.Fatal(err)
		}
		raw, err = run.Run(ctx, "journalctl", "--no-pager", "--quiet", "-o", "json", "_TRANSPORT=kernel", "--since="+journalPageTime(from), "-n", "500")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, "netos "+name+": ") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(raw, "netos "+name+": ") {
		t.Fatal("generated LOG not observed in kernel journal")
	}
	to := time.Now().UTC().Truncate(time.Microsecond)
	filters := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339Nano)) + "&object=" + name
	var first []logEntry
	for repeat := 0; repeat < 3; repeat++ {
		data := readAllJournalPages(t, &Server{StorageRunner: run}, "firewall", filters)
		if len(data.Entries) != 1 {
			t.Fatalf("expected one actual packet, got %d", len(data.Entries))
		}
		e := data.Entries[0]
		for _, field := range []string{"netos " + name + ": ", "OUT=lo", "SRC=127.0.0.1", "DST=127.0.0.1", "PROTO=UDP", "DPT=" + port} {
			if !strings.Contains(e.Message, field) {
				t.Fatalf("missing %s", field)
			}
		}
		if e.Result != "" || e.Unit != "kernel" {
			t.Fatal("invented outcome or lost source", e)
		}
		if repeat == 0 {
			first = data.Entries
		} else if !reflect.DeepEqual(first, data.Entries) {
			t.Fatal("snapshot changed")
		}
	}
	// Compare the selected actual packet against the old text selector.
	legacy, err := run.Run(ctx, "journalctl", "--no-pager", "--quiet", "-o", "json", "_TRANSPORT=kernel", "--grep=netos ", "--since="+journalPageTime(from), "--until="+journalPageTime(to), "-n", "300")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseJournalEntries(legacy, "firewall")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Message == first[0].Message && e.Time == first[0].Time {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy packet changed")
	}
}

func TestIntegrationFirewallPageKernelNoise(t *testing.T) {
	if os.Getenv("NETOS_LOGS_INTEGRATION") != "1" {
		t.Skip("requires authorized root test machine")
	}
	ctx := context.Background()
	run := &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	for _, count := range []int{30, 3000} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			from := time.Now().UTC().Truncate(time.Microsecond)
			tag := "qa-kernel-noise-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			for i := 0; i < count; i++ {
				// Separate writers exercise kernel ingestion without changing sysctls.
				f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("<6>" + tag + " " + strconv.Itoa(i) + "\n")
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			observed := 0
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if _, err := run.Run(ctx, "journalctl", "--sync"); err != nil {
					t.Fatal(err)
				}
				raw, err := run.Run(ctx, "journalctl", "--no-pager", "--quiet", "-o", "json", "--output-fields=MESSAGE", "_TRANSPORT=kernel", "--since="+journalPageTime(from), "-n", strconv.Itoa(count+100))
				if err != nil {
					t.Fatal(err)
				}
				observed = strings.Count(raw, tag)
				if observed == count {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if observed != count {
				t.Fatalf("kernel fixture lost records: %d/%d", observed, count)
			}
			to := time.Now().UTC().Truncate(time.Microsecond)
			filter := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339Nano)) + "&object=" + tag
			for repeat := 0; repeat < 3; repeat++ {
				start := time.Now()
				p := readAllJournalPages(t, &Server{StorageRunner: run}, "firewall", filter)
				if len(p.Entries) != 0 {
					t.Fatal("non-firewall kernel noise displayed")
				}
				t.Logf("kernel records=%d repeat=%d total=%s", count, repeat, time.Since(start))
			}
		})
	}
}
