package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	netosruntime "github.com/netos-router/netos/internal/runtime"
)

type observationRunner struct {
	failRules       bool
	failParsedRoute bool
	routeCalls      int
}

func (r *observationRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, " rule show") {
		if r.failRules {
			return "", fmt.Errorf("injected rule failure")
		}
		return "0: from all lookup local\n", nil
	}
	if strings.Contains(command, " route show") {
		r.routeCalls++
		if r.failParsedRoute && r.routeCalls > 1 {
			return "", fmt.Errorf("injected parsed-route failure")
		}
		return "default via 192.0.2.1 dev br0 proto 201 metric 10\n", nil
	}
	if strings.Contains(command, " neigh show") {
		return "192.168.50.10 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n", nil
	}
	return "", nil
}

func (r *observationRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func observationServer(t *testing.T, runner *observationRunner) *Server {
	t.Helper()
	lease := filepath.Join(t.TempDir(), "dnsmasq.leases")
	if err := os.WriteFile(lease, []byte("4102444800 aa:bb:cc:dd:ee:ff 192.168.50.10 printer *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := apply.NewEngine(nil, true)
	if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	// The observation handlers only need the already-applied topology. Mutating
	// this isolated test engine avoids coupling the fixture to unrelated full
	// configuration validation requirements.
	cfg := engine.Current()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Interface: "lan-if", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.Clients = []config.Client{{MAC: "aa:bb:cc:dd:ee:ff", Name: "Printer", Channel: "direct", Blocked: true}}
	collector := netosruntime.NewCollector(runner, lease)
	collector.SysClassNet = filepath.Join(t.TempDir(), "net")
	base := filepath.Join(collector.SysClassNet, "br0")
	values := map[string]string{
		"address": "aa:bb:cc:dd:ee:01\n", "mtu": "1500\n", "operstate": "up\n", "flags": "0x1003\n",
		"statistics/rx_bytes": "100\n", "statistics/tx_bytes": "200\n",
		"statistics/rx_packets": "3\n", "statistics/tx_packets": "4\n",
		"statistics/rx_errors": "0\n", "statistics/tx_errors": "1\n",
	}
	for name, value := range values {
		path := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{Engine: engine, Collector: collector}
}

func TestObservationHandlersReturnLiveData(t *testing.T) {
	s := observationServer(t, &observationRunner{})
	for _, path := range []string{"/api/clients", "/api/interfaces", "/api/leases", "/api/arp", "/api/routes?table=main"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		switch {
		case strings.HasPrefix(path, "/api/clients"):
			s.handleClients(w, r)
		case strings.HasPrefix(path, "/api/leases"):
			s.handleLeases(w, r)
		case strings.HasPrefix(path, "/api/interfaces"):
			s.handleInterfaces(w, r)
		case strings.HasPrefix(path, "/api/arp"):
			s.handleARP(w, r)
		default:
			s.handleRoutes(w, r)
		}
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "aa:bb:cc:dd:ee:ff") && !strings.HasPrefix(path, "/api/routes") && !strings.HasPrefix(path, "/api/interfaces") {
			t.Fatalf("%s lost observed client: %s", path, w.Body.String())
		}
	}
	if !strings.Contains(serveStatus(t, s), `"clients_online":1`) {
		t.Fatal("status did not report the observed online client")
	}

	w := httptest.NewRecorder()
	s.handleClients(w, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	var response struct {
		Clients []struct {
			Name    string `json:"name"`
			Blocked bool   `json:"blocked"`
			Online  bool   `json:"online"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Clients) != 1 || response.Clients[0].Name != "Printer" || !response.Clients[0].Blocked || !response.Clients[0].Online {
		t.Fatalf("client enrichment=%+v", response.Clients)
	}
}

func serveStatus(t *testing.T, s *Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(path, []byte("123.75 10.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath := procUptimePath
	procUptimePath = path
	t.Cleanup(func() { procUptimePath = oldPath })
	w := httptest.NewRecorder()
	s.handleStatus(w, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"uptime_seconds":123`) || !strings.Contains(w.Body.String(), `"br0"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

func TestObservationHandlersDoNotHideCollectorFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner *observationRunner
	}{
		{"rules", &observationRunner{failRules: true}},
		{"parsed route", &observationRunner{failParsedRoute: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := observationServer(t, tc.runner)
			w := httptest.NewRecorder()
			s.handleRoutes(w, httptest.NewRequest(http.MethodGet, "/api/routes", nil))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	s := &Server{}
	for _, handler := range []http.HandlerFunc{s.handleStatus, s.handleClients, s.handleInterfaces, s.handleLeases, s.handleARP, s.handleRoutes} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("nil collector status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestStatisticsStrictQueryValidationAndFiltering(t *testing.T) {
	// Keep the fixture inside the handler's real-time query window. A fixed
	// timestamp eventually falls outside ?hours=1 even when filtering works.
	now := time.Now().UTC().Truncate(time.Second)
	history := &netosruntime.TrafficHistory{
		Path: filepath.Join(t.TempDir(), "traffic.jsonl"), Interval: time.Hour, Retain: 7 * 24 * time.Hour,
		Now: func() time.Time { return now },
		Collect: func() ([]netosruntime.InterfaceStat, error) {
			return []netosruntime.InterfaceStat{{Name: "br0", RXBytes: 100, TXBytes: 200}}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	history.Run(ctx)
	s := &Server{Traffic: history}

	for _, path := range []string{
		"/api/statistics?hours=abc",
		"/api/statistics?hours=0",
		"/api/statistics?hours=169",
		"/api/statistics?interfaces=bad%20name",
		"/api/statistics?interfaces=interface-name-too-long",
	} {
		w := httptest.NewRecorder()
		s.handleStatistics(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.handleStatistics(w, httptest.NewRequest(http.MethodGet, "/api/statistics?hours=1&interfaces=br0", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"br0"`) || !strings.Contains(w.Body.String(), `"interval_seconds":3600`) {
		t.Fatalf("valid statistics status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestVPNServerCertificateLifecycle(t *testing.T) {
	root := t.TempDir()
	oldRoot := vpnGeneratedDir
	vpnGeneratedDir = root
	t.Cleanup(func() { vpnGeneratedDir = oldRoot })

	engine := apply.NewEngine(nil, true)
	if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	engine.Current().VPNServers = []config.VPNServer{
		{ID: "oc", Index: 7, Enabled: true, Type: "ocserv"},
		{ID: "ike", Index: 8, Enabled: true, Type: "ikev2"},
		{ID: "off", Index: 9, Enabled: false, Type: "ocserv"},
	}
	for path, content := range map[string]string{
		filepath.Join(root, "ocserv-srv7-tls", "panel.crt"):     "oc-cert",
		filepath.Join(root, "strongswan", "x509", "server.crt"): "ike-cert",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Engine: engine}
	for _, tc := range []struct {
		id, content, filename string
		want                  int
	}{
		{"oc", "oc-cert", "netos-openconnect-7.crt", http.StatusOK},
		{"ike", "ike-cert", "netos-ikev2-8-ca.crt", http.StatusOK},
		{"off", "", "", http.StatusNotFound},
		{"missing", "", "", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/vpn-servers/"+tc.id+"/certificate", nil)
		r.SetPathValue("id", tc.id)
		s.handleVPNServerCertificate(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s status=%d body=%s", tc.id, w.Code, w.Body.String())
		}
		if tc.want == http.StatusOK && (w.Body.String() != tc.content || !strings.Contains(w.Header().Get("Content-Disposition"), tc.filename)) {
			t.Fatalf("%s headers=%v body=%q", tc.id, w.Header(), w.Body.String())
		}
	}

	missingPath := filepath.Join(root, "ocserv-srv7-tls", "panel.crt")
	if err := os.Remove(missingPath); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetPathValue("id", "oc")
	s.handleVPNServerCertificate(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing cert status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	(&Server{}).handleVPNServerCertificate(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil engine status=%d body=%s", w.Code, w.Body.String())
	}
}
