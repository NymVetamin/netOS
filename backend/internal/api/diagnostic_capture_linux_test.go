//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDiagnosticLinuxCaptureMACAny(t *testing.T) {
	diagnosticLinux(t)
	name := fmt.Sprintf("cap%d", os.Getpid())
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("netns", "add", name)
	defer exec.Command("ip", "netns", "del", name).Run()
	run("link", "add", name, "type", "veth", "peer", "name", name+"p")
	defer exec.Command("ip", "link", "del", name).Run()
	run("link", "set", name+"p", "netns", name)
	run("addr", "add", "198.18.11.1/30", "dev", name)
	run("link", "set", name, "up")
	run("-n", name, "link", "set", name+"p", "address", "02:00:00:00:11:02")
	run("-n", name, "addr", "add", "198.18.11.2/30", "dev", name+"p")
	run("-n", name, "link", "set", name+"p", "up")
	run("-n", name, "link", "set", "lo", "up")
	s := &Server{}
	defer s.stopDiagnostics()
	for _, kind := range []string{"capture", "torch"} {
		for _, direction := range []string{"inout", "in", "out"} {
			body, _ := json.Marshal(diagnosticInput{Kind: kind, MAC: "02:00:00:00:11:02", Address: "198.18.11.2", Protocol: "icmp", Direction: direction})
			r := httptest.NewRequest("POST", "/", bytes.NewReader(body)).WithContext(context.WithValue(context.Background(), ctxUser, "test"))
			w := httptest.NewRecorder()
			s.handleDiagnosticStart(w, r)
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			var result struct{ ID string }
			json.Unmarshal(w.Body.Bytes(), &result)
			s.diagnostics.mu.Lock()
			j := s.diagnostics.jobs[result.ID]
			s.diagnostics.mu.Unlock()
			time.Sleep(400 * time.Millisecond)
			run("netns", "exec", name, "ping", "-c", "2", "-i", "0.1", "-W", "1", "198.18.11.1")
			time.Sleep(100 * time.Millisecond)
			r = httptest.NewRequest("DELETE", "/", nil).WithContext(context.WithValue(context.Background(), ctxUser, "test"))
			r.SetPathValue("id", j.id)
			s.handleDiagnosticStop(httptest.NewRecorder(), r)
			select {
			case <-j.done:
			case <-time.After(5 * time.Second):
				t.Fatal("capture did not stop")
			}
			if j.state != "stopped" {
				t.Fatal(j.state, j.failure, j.output.String())
			}
			reader := j.torch
			if kind == "capture" {
				reader = newTorchReader()
				data, err := os.ReadFile(j.pcap.Name())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = reader.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			wanted := 2
			if direction == "inout" {
				wanted = 4
			}
			if reader.packets != uint64(wanted) {
				t.Fatalf("%s %s packets=%d want=%d %s", kind, direction, reader.packets, wanted, j.output.String())
			}
		}
	}
}
