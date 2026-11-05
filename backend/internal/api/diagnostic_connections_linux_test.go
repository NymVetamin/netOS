//go:build linux

package api

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticLinuxConnections(t *testing.T) {
	diagnosticLinux(t)
	// Exercise the real local-socket path in the runner.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	result, err := readConnections(context.Background(), "local", connectionFilter{ports: [][2]uint16{{port, port}}}, 0)
	if err != nil || result.Total == 0 || result.Rows[0].State != "LISTEN" {
		t.Fatal(result, err)
	}
	// Two namespaces provide real NAT traffic without modifying the host firewall.
	prefix := fmt.Sprintf("cn%d", os.Getpid())
	client, router := prefix+"c", prefix+"r"
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
		return string(out)
	}
	for _, ns := range []string{client, router} {
		run("netns", "add", ns)
		defer exec.Command("ip", "netns", "del", ns).Run()
		run("-n", ns, "link", "set", "lo", "up")
	}
	run("link", "add", prefix+"a", "type", "veth", "peer", "name", prefix+"b")
	run("link", "set", prefix+"a", "netns", client)
	run("link", "set", prefix+"b", "netns", router)
	run("-n", client, "addr", "add", "198.18.21.2/30", "dev", prefix+"a")
	run("-n", router, "addr", "add", "198.18.21.1/30", "dev", prefix+"b")
	run("-n", client, "link", "set", prefix+"a", "up")
	run("-n", router, "link", "set", prefix+"b", "up")
	run("netns", "exec", router, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "18081", "-j", "REDIRECT", "--to-ports", "18082")
	run("netns", "exec", router, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")

	server := exec.Command("ip", "netns", "exec", router, "python3", "-u", "-c", "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',18082)); s.listen(); print('ready',flush=True); c,a=s.accept(); c.recv(100); c.sendall(b'reply'); time.sleep(20)")
	ready, _ := server.StdoutPipe()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal(line, err)
	}
	dial := exec.Command("ip", "netns", "exec", client, "python3", "-u", "-c", "import socket,time; s=socket.create_connection(('198.18.21.1',18081)); s.sendall(b'test'); s.recv(100); print('ready',flush=True); time.sleep(20)")
	ready, _ = dial.StdoutPipe()
	if err := dial.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { dial.Process.Kill(); dial.Wait() }()
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal(line, err)
	}
	for i := 0; i < 2; i++ {
		out := run("netns", "exec", router, "conntrack", "-L", "-f", "ipv4", "-o", "extended")
		// conntrack writes its summary to stderr; scan only the matching entry.
		found := false
		for _, line := range strings.Split(out, "\n") {
			row, ok := parseTrackedConnection(line)
			if ok && row.Destination.Port == strconv.Itoa(18081) {
				found = true
				if row.NAT != "DNAT" || row.ReplySource.Port != "18082" || row.State != "ESTABLISHED" || row.Bytes == nil || *row.Bytes == 0 {
					t.Fatal(row)
				}
			}
		}
		if !found {
			t.Fatal(out)
		}
	}
	dial.Process.Kill()
	dial.Wait()
	time.Sleep(100 * time.Millisecond)
	out := run("netns", "exec", router, "conntrack", "-L", "-f", "ipv4", "-o", "extended")
	if !strings.Contains(out, "src=198.18.21.2") {
		t.Fatal("connection state disappeared unexpectedly", out)
	}
	if _, err := readConnections(context.Background(), "tracked", connectionFilter{}, 0); err != nil {
		t.Fatal(err)
	}

}
