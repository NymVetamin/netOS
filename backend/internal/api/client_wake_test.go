package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestWakePacket(t *testing.T) {
	p, err := wakePacket("02:11:22:33:44:55")
	if err != nil || len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{255}, 6)) {
		t.Fatal(p, err)
	}
	for i := 6; i < len(p); i += 6 {
		if !bytes.Equal(p[i:i+6], []byte{2, 17, 34, 51, 68, 85}) {
			t.Fatal("incorrect MAC repetition")
		}
	}
	for _, mac := range []string{"", "bad", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:11:22:33:44:55", "02:11:22:33:44:55:66:77"} {
		if _, err := wakePacket(mac); err == nil {
			t.Fatalf("accepted %q", mac)
		}
	}
}

func TestWakeInterfaceAndPermissions(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "lan", Name: "br-lan", Enabled: true}, {ID: "wan", Name: "eth0", Enabled: true}}
	c.Networks = []config.Network{{ID: "home", Interface: "lan", Enabled: true}}
	if name, err := wakeInterface(c, "home"); err != nil || name != "br-lan" {
		t.Fatal(name, err)
	}
	for _, id := range []string{"", "wan", "eth0", "missing"} {
		if _, err := wakeInterface(c, id); err == nil {
			t.Fatal(id)
		}
	}
	c.Networks[0].Enabled = false
	if _, err := wakeInterface(c, "home"); err == nil {
		t.Fatal("disabled network")
	}
	c.Networks[0].Enabled = true
	c.Interfaces[0].Enabled = false
	if _, err := wakeInterface(c, "home"); err == nil {
		t.Fatal("disabled interface")
	}
	for _, level := range []string{"none", "view", "manage"} {
		r := limitedRequest(map[string]string{"clients": level})
		r.Method = "POST"
		r.URL.Path = "/api/clients/wake"
		if limitedEndpoint(r) != (level == "manage") {
			t.Fatal(level)
		}
		r.Method = "GET"
		if limitedEndpoint(r) || viewerAllowed(r) {
			t.Fatal("read-only role may wake")
		}
	}
}

func TestWakeAuthAndInvalidInput(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	for _, tc := range []struct {
		body        string
		auth, token bool
		want        int
	}{
		{`{}`, false, false, 401}, {`{}`, true, false, 403},
		{`{"mac":"bad","network":"home"}`, true, true, 400},
		{`{"mac":"02:11:22:33:44:55","interface":"eth0"}`, true, true, 400},
		{`{} {}`, true, true, 400}, {strings.Repeat("x", 1025), true, true, 400},
	} {
		r := httptest.NewRequest("POST", "/api/clients/wake", strings.NewReader(tc.body))
		if tc.auth {
			r.AddCookie(cookie)
		}
		if tc.token {
			r.Header.Set(csrfHeader, csrf)
		}
		w := httptest.NewRecorder()
		s.requireAuth(s.handleClientWake).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status %d want%d: %s", w.Code, tc.want, w.Body)
		}
	}
	r := limitedRequest(map[string]string{"clients": "view"})
	r.Method = http.MethodPost
	w := httptest.NewRecorder()
	s.handleClientWake(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func BenchmarkWakeSelection(b *testing.B) {
	for _, n := range []int{5, 2500} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := config.Default()
			c.Networks = nil
			c.Interfaces = nil
			for i := 0; i < n; i++ {
				id := fmt.Sprint(i)
				c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: "eth" + id, Enabled: true})
				c.Networks = append(c.Networks, config.Network{ID: id, Interface: id, Enabled: true})
			}
			id := fmt.Sprint(n - 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := wakeInterface(c, id); err != nil {
					b.Fatal(err)
				}
				if _, err := wakePacket("02:11:22:33:44:55"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
