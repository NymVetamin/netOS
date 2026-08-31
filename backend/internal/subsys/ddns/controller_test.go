package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func baseConfig(provider string) *config.Config {
	cfg := config.Default()
	cfg.DDNS = config.DDNS{
		Enabled: true, Provider: provider, Hostname: "router.example.test", AddressSource: "web",
		Interval: 60, Token: "secret-token", Username: "user", Password: "pass", ZoneID: "zone", RecordID: "record",
	}
	return cfg
}

func TestDuckDNSUpdateAndStatus(t *testing.T) {
	called := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.URL.Query().Get("domains") != "router.example.test" || r.URL.Query().Get("token") != "secret-token" || r.URL.Query().Get("ip") != "203.0.113.9" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	c := New(nil)
	c.DuckEndpoint = server.URL
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "203.0.113.9", nil }
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	cfg := baseConfig("duckdns")
	c.tick(context.Background(), cfg)
	status := c.Status()
	if called != 1 || !status.Success || status.Address != "203.0.113.9" || !status.NextRun.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected result: calls=%d status=%+v", called, status)
	}
	c.tick(context.Background(), cfg)
	if called != 1 {
		t.Fatalf("early duplicate update: %d", called)
	}
}

func TestCloudflareRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/zones/zone/dns_records/record" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Error("missing bearer token")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["content"] != "198.51.100.7" || body["name"] != "router.example.test" {
			t.Errorf("unexpected body: %#v", body)
		}
		if _, exists := body["proxied"]; exists {
			t.Error("partial update must preserve the Cloudflare proxy setting")
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()
	c := New(nil)
	c.CloudEndpoint = server.URL
	if err := c.update(context.Background(), baseConfig("cloudflare").DDNS, "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
}

func TestNoIPRejectsProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "pass" {
			t.Error("missing basic auth")
		}
		_, _ = w.Write([]byte("badauth"))
	}))
	defer server.Close()
	c := New(nil)
	c.NoIPEndpoint = server.URL
	err := c.update(context.Background(), baseConfig("noip").DDNS, "192.0.2.4")
	if err == nil || !strings.Contains(err.Error(), "отклонил") {
		t.Fatalf("provider error was ignored: %v", err)
	}
}

func TestNoIPSuccessfulUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "pass" {
			t.Error("missing basic auth")
		}
		if r.URL.Query().Get("hostname") != "router.example.test" || r.URL.Query().Get("myip") != "192.0.2.4" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte("good 192.0.2.4"))
	}))
	defer server.Close()
	c := New(nil)
	c.NoIPEndpoint = server.URL
	if err := c.update(context.Background(), baseConfig("noip").DDNS, "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
}

func TestCloudflareRejectsUnsuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}))
	defer server.Close()
	c := New(nil)
	c.CloudEndpoint = server.URL
	if err := c.update(context.Background(), baseConfig("cloudflare").DDNS, "198.51.100.7"); err == nil {
		t.Fatal("Cloudflare failure was accepted")
	}
}

func TestWebAddressMustBeIPv4(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not-an-ip")) }))
	defer server.Close()
	c := New(nil)
	c.AddressEndpoint = server.URL
	_, err := c.resolveAddress(context.Background(), baseConfig("duckdns"))
	if err == nil {
		t.Fatal("invalid address was accepted")
	}
}
