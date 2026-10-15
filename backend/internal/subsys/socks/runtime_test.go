package socks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional real Xray check. Binds loopback only, never a router or public port.
func TestSocksRealXray(t *testing.T) {
	binaryPath := os.Getenv("NETOS_TEST_XRAY")
	if binaryPath == "" {
		t.Skip("set NETOS_TEST_XRAY to the pinned Xray executable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	c := fixture()
	c.Socks.Port = port
	data, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
	data, _ = json.Marshal(doc)
	file := filepath.Join(t.TempDir(), "socks.json")
	os.WriteFile(file, data, 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binaryPath, "run", "-test", "-config", file).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	cmd := exec.CommandContext(ctx, binaryPath, "run", "-config", file)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 60; i++ {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	auth := func(password string) net.Conn {
		t.Helper()
		conn, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{5, 1, 2})
		reply := make([]byte, 2)
		if _, e = io.ReadFull(conn, reply); e != nil || reply[1] != 2 {
			t.Fatalf("auth negotiation %v %v", reply, e)
		}
		packet := append([]byte{1, 4}, []byte("test")...)
		packet = append(packet, byte(len(password)))
		packet = append(packet, []byte(password)...)
		conn.Write(packet)
		if _, e = io.ReadFull(conn, reply); e != nil {
			t.Fatal(e)
		}
		if password != "test-password" {
			if reply[1] == 0 {
				t.Fatal("wrong password accepted")
			}
			conn.Close()
			return nil
		}
		if reply[1] != 0 {
			t.Fatal("correct password rejected")
		}
		return conn
	}
	auth("wrong-password")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "socks-runtime-ok") }))
	defer target.Close()
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port
	conn := auth("test-password")
	defer conn.Close()
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
	conn.Write(request)
	reply := make([]byte, 10)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("connect %v %v", reply, err)
	}
	fmt.Fprint(conn, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "socks-runtime-ok") {
		t.Fatal(string(body))
	}
	// UDP associate must be explicitly rejected by the actual Xray server.
	control := auth("test-password")
	defer control.Close()
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err = io.ReadFull(control, reply); err != nil || reply[1] == 0 {
		t.Fatalf("UDP should be unavailable: %v %v", reply, err)
	}
}

// Exercise the actual candidate filename and validation command used by Apply.
// Only systemctl is substituted; Xray loads the candidate from disk itself.
type validationRunner struct {
	fake
	binary string
}

func (r *validationRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "/usr/local/bin/xray" {
		out, err := exec.CommandContext(ctx, r.binary, args...).CombinedOutput()
		return string(out), err
	}
	return r.fake.Run(ctx, name, args...)
}
func TestSocksApplyRealXrayValidation(t *testing.T) {
	binary := os.Getenv("NETOS_TEST_XRAY")
	if binary == "" {
		t.Skip("set NETOS_TEST_XRAY to the pinned Xray executable")
	}
	root := t.TempDir()
	s := New(&validationRunner{binary: binary}, root)
	s.UnitDir = filepath.Join(root, "units")
	if err := s.Apply(context.Background(), fixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "socks.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "socks.candidate.json")); !os.IsNotExist(err) {
		t.Fatal("candidate left behind", err)
	}
}
