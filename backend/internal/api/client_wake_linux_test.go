package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"

	"golang.org/x/sys/unix"
)

func TestWakeLinuxPacket(t *testing.T) {
	if os.Getenv("NETOS_WOL_TEST") != "1" {
		t.Skip("isolated root Linux namespace required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == host {
		t.Fatal("refusing host namespace")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("link", "add", "wola", "type", "veth", "peer", "name", "wolb")
	defer exec.Command("ip", "link", "del", "wola").Run()
	ip("link", "set", "wola", "up")
	ip("link", "set", "wolb", "up")
	packet, _ := wakePacket("02:11:22:33:44:55")
	s, cookie, csrf := newAuthedServer(t)
	s.Engine = apply.NewEngine(nil, true)
	if _, err := s.Engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	cfg := s.Engine.Current()
	cfg.Networks = []config.Network{{ID: "home", Interface: "test", Enabled: true}}
	check := func(sender, receiver string) {
		t.Helper()
		iface, err := net.InterfaceByName(receiver)
		if err != nil {
			t.Fatal(err)
		}
		protocol := binary.NativeEndian.Uint16([]byte{0x08, 0x42})
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(protocol))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index}); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 2; repeat++ {
			cfg.Interfaces = []config.Interface{{ID: "test", Name: sender, Enabled: true}}
			r := httptest.NewRequest("POST", "/api/clients/wake", strings.NewReader(`{"mac":"02:11:22:33:44:55","network":"home"}`))
			r.AddCookie(cookie)
			r.Header.Set(csrfHeader, csrf)
			w := httptest.NewRecorder()
			s.requireAuth(s.handleClientWake).ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("wake API: %d %s", w.Code, w.Body)
			}
			buf := make([]byte, 2048)
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				t.Fatal(err)
			}
			if n != 116 || !bytes.Equal(buf[:6], bytes.Repeat([]byte{255}, 6)) || !bytes.Equal(buf[12:14], []byte{0x08, 0x42}) || !bytes.Equal(buf[14:n], packet) {
				t.Fatalf("bad frame %x", buf[:n])
			}
		}
	}
	check("wola", "wolb")
	ip("link", "add", "wolbr", "type", "bridge")
	defer exec.Command("ip", "link", "del", "wolbr").Run()
	ip("link", "set", "wola", "master", "wolbr")
	ip("link", "set", "wolbr", "up")
	check("wolbr", "wolb")
	ip("link", "set", "wola", "nomaster")
	ip("link", "add", "link", "wola", "name", "wola42", "type", "vlan", "id", "42")
	ip("link", "add", "link", "wolb", "name", "wolb42", "type", "vlan", "id", "42")
	ip("link", "set", "wola42", "up")
	ip("link", "set", "wolb42", "up")
	check("wola42", "wolb42")
	ip("link", "set", "wola42", "down")
	for _, name := range []string{"wola42", "missing-wol", "lo"} {
		if err := sendWakePacket(name, packet); err == nil {
			t.Fatalf("accepted unavailable/non-Ethernet %s", name)
		}
	}
	ip("link", "set", "wola42", "up")
	check("wola42", "wolb42")
}

func TestWakeLinuxRequestScaling(t *testing.T) {
	if os.Getenv("NETOS_WOL_TEST") != "1" {
		t.Skip("isolated root Linux namespace required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == host {
		t.Fatal("refusing host namespace")
	}
	s, cookie, csrf := newAuthedServer(t)
	s.Engine = apply.NewEngine(nil, true)
	if _, err := s.Engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	cfg := s.Engine.Current()
	cfg.Networks = nil
	cfg.Interfaces = nil
	last := 0
	for _, n := range []int{5, 500} {
		var commands strings.Builder
		for i := last; i < n; i++ {
			name := fmt.Sprintf("wbench%d", i)
			fmt.Fprintf(&commands, "link add %s type dummy\nlink set %s up\n", name, name)
			cfg.Interfaces = append(cfg.Interfaces, config.Interface{ID: name, Name: name, Enabled: true})
			cfg.Networks = append(cfg.Networks, config.Network{ID: name, Interface: name, Enabled: true})
		}
		cmd := exec.Command("ip", "-batch", "-")
		cmd.Stdin = strings.NewReader(commands.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
		last = n
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		for i := 0; i < 20; i++ {
			r := httptest.NewRequest("POST", "/api/clients/wake", strings.NewReader(fmt.Sprintf(`{"mac":"02:11:22:33:44:55","network":"wbench%d"}`, n-1)))
			r.AddCookie(cookie)
			r.Header.Set(csrfHeader, csrf)
			w := httptest.NewRecorder()
			s.requireAuth(s.handleClientWake).ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		t.Logf("interfaces=%d full_authenticated_request_ms=%.3f allocated_bytes=%d", n, float64(elapsed.Nanoseconds())/20e6, (after.TotalAlloc-before.TotalAlloc)/20)
	}
}
