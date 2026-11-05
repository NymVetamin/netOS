//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Explicitly opt in on an isolated Linux runner, never on a user's router.
func diagnosticLinux(t *testing.T) {
	t.Helper()
	if os.Getenv("NETOS_DIAGNOSTIC_LINUX_TEST") != "1" {
		t.Skip("requires isolated Linux runner with diagnostic packages")
	}
	for _, name := range []string{"ping", "traceroute", "mtr", "dig", "tcpdump", "iperf3", "ip", "ss"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
}
func diagnosticExecute(t *testing.T, in diagnosticInput) []byte {
	t.Helper()
	c, err := buildDiagnosticCommand(in)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.duration)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.name, c.args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", c.name, c.args, err, out)
	}
	return out
}
func TestDiagnosticLinuxCommands(t *testing.T) {
	diagnosticLinux(t)
	for _, kind := range []string{"ping", "traceroute", "mtr", "route", "connections"} {
		t.Run(kind, func(t *testing.T) {
			out := diagnosticExecute(t, diagnosticInput{Kind: kind, Host: "127.0.0.1", Interface: "lo", Count: 1, TTL: 3})
			if len(out) == 0 {
				t.Fatal("empty output")
			}
		})
	}
	// Local DNS response: no external resolver or internet dependency.
	server, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 12 {
				buf[2] |= 0x80
				buf[3] = 0x80
				_, _ = server.WriteTo(buf[:n], addr)
			}
		}
	}()
	if out := diagnosticExecute(t, diagnosticInput{Kind: "dns", Host: "example.test", DNSServer: "127.0.0.1"}); !bytes.Contains(out, []byte("status: NOERROR")) {
		t.Fatal(string(out))
	}
	for _, udp := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			c, err := buildDiagnosticCommand(diagnosticInput{Kind: "iperf", Mode: "server", Bind: "127.0.0.1", Port: port, Duration: 10})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), c.duration)
			cmd := exec.CommandContext(ctx, c.name, c.args...)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			out := diagnosticExecute(t, diagnosticInput{Kind: "iperf", Host: "127.0.0.1", Bind: "127.0.0.1", Port: port, Duration: 1, Mbps: 1, UDP: udp, Reverse: reverse})
			err = cmd.Wait()
			cancel()
			if err != nil {
				t.Fatalf("server: %v %s", err, output.String())
			}
			if !bytes.Contains(out, []byte("receiver")) {
				t.Fatal(string(out))
			}
		}
	}
}

func TestDiagnosticLinuxLifecycle(t *testing.T) {
	diagnosticLinux(t)
	s := &Server{}
	t.Cleanup(func() {
		s.diagnostics.mu.Lock()
		defer s.diagnostics.mu.Unlock()
		for _, j := range s.diagnostics.jobs {
			j.cancel()
			if j.expiry != nil {
				j.expiry.Stop()
			}
		}
	})
	start := func(in diagnosticInput, want int) string {
		body, _ := json.Marshal(in)
		r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, "tester"))
		w := httptest.NewRecorder()
		s.handleDiagnosticStart(w, r)
		if w.Code != want {
			t.Fatalf("start %d: %s", w.Code, w.Body.String())
		}
		var result struct{ ID string }
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return result.ID
	}
	request := func(id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, "tester"))
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.handleDiagnosticJob(w, r)
		return w
	}
	wait := func(id string) map[string]any {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			var result map[string]any
			w := request(id)
			_ = json.Unmarshal(w.Body.Bytes(), &result)
			state := result["state"]
			if state != "running" && state != "stopping" {
				return result
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("job did not finish")
		return nil
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	for _, kind := range []string{"capture", "torch"} {
		id := start(diagnosticInput{Kind: kind, Interface: "lo", Filter: "udp port " + strconv.Itoa(port), Duration: 3, Count: 20}, 202)
		start(diagnosticInput{Kind: "ping", Host: "127.0.0.1"}, 409)
		time.Sleep(300 * time.Millisecond)
		client, err := net.Dial("udp4", udp.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 30; i++ {
			_, _ = client.Write([]byte("diagnostic-local-test"))
			time.Sleep(10 * time.Millisecond)
		}
		client.Close()
		result := wait(id)
		if result["state"] != "done" {
			t.Fatalf("%s: %#v", kind, result)
		}
		if kind == "torch" {
			torch := result["torch"].(map[string]any)
			if torch["packets"].(float64) == 0 {
				t.Fatal(result)
			}
		} else {
			r := httptest.NewRequest("GET", "/", nil)
			r = r.WithContext(context.WithValue(r.Context(), ctxUser, "tester"))
			r.SetPathValue("id", id)
			w := httptest.NewRecorder()
			s.handleDiagnosticCapture(w, r)
			if w.Code != 200 || len(w.Body.Bytes()) <= 24 {
				t.Fatal(w.Code, result)
			}
			parser := newTorchReader()
			if _, err := parser.Write(w.Body.Bytes()); err != nil || parser.packets == 0 {
				t.Fatal(err)
			}
		}
	}
	id := start(diagnosticInput{Kind: "capture", Interface: "lo", Filter: "udp port " + strconv.Itoa(port), Duration: 60}, 202)
	time.Sleep(200 * time.Millisecond)
	r := httptest.NewRequest("DELETE", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, "tester"))
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.handleDiagnosticStop(w, r)
	s.handleDiagnosticStop(httptest.NewRecorder(), r)
	if result := wait(id); result["state"] != "stopped" {
		t.Fatal(result)
	}
	id = start(diagnosticInput{Kind: "capture", Interface: "lo", Filter: "not (", Duration: 1}, 202)
	if result := wait(id); result["state"] != "error" {
		t.Fatal(result)
	}
	id = start(diagnosticInput{Kind: "capture", Interface: "lo", Filter: "udp port " + strconv.Itoa(port), Duration: 1}, 202)
	if result := wait(id); result["state"] != "done" {
		t.Fatal(result)
	}
	id = start(diagnosticInput{Kind: "ping", Host: "127.0.0.1", Count: 1}, 202)
	if result := wait(id); result["state"] != "done" {
		t.Fatal(result)
	}
	s.diagnostics.mu.Lock()
	n := len(s.diagnostics.jobs)
	s.diagnostics.mu.Unlock()
	if n > 4 {
		t.Fatal("unbounded retained jobs", n)
	}
}
