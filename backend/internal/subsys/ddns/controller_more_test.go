package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestStatusJSONOmitsDatesBeforeFirstAttempt(t *testing.T) {
	data, err := json.Marshal(Status{Enabled: true, Provider: "duckdns"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "last_run") || strings.Contains(text, "next_run") || strings.Contains(text, "0001-") {
		t.Fatalf("zero attempt dates leaked into status JSON: %s", text)
	}
}

type captureLogger struct {
	mu    sync.Mutex
	infos []string
	warns []string
}

func (l *captureLogger) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, format)
}

func (l *captureLogger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, format)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func TestPlanEveryTransition(t *testing.T) {
	c := New(nil)
	disabled := config.Default()
	if actions, err := c.Plan(disabled, disabled); err != nil || len(actions) != 0 {
		t.Fatalf("unchanged default: actions=%v err=%v", actions, err)
	}
	if actions, err := c.Plan(nil, disabled); err != nil || len(actions) != 1 || actions[0].Kind != "delete" {
		t.Fatalf("initial explicit defaults: actions=%v err=%v", actions, err)
	}

	enabledValue := *disabled
	enabled := &enabledValue
	enabled.DDNS = baseConfig("duckdns").DDNS
	actions, err := c.Plan(disabled, enabled)
	if err != nil || len(actions) != 1 || actions[0].Kind != "create" || actions[0].Subsystem != "ddns" || actions[0].Detail != enabled.DDNS.Hostname {
		t.Fatalf("enable plan: actions=%+v err=%v", actions, err)
	}
	changedValue := *enabled
	changed := &changedValue
	changed.DDNS.Hostname = "changed.example.test"
	actions, err = c.Plan(enabled, changed)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("update plan: actions=%+v err=%v", actions, err)
	}
	actions, err = c.Plan(changed, disabled)
	if err != nil || len(actions) != 1 || actions[0].Kind != "delete" {
		t.Fatalf("disable plan: actions=%+v err=%v", actions, err)
	}
}

func TestApplyPreservesScheduleUntilDDNSChanges(t *testing.T) {
	c := New(nil)
	cfg := baseConfig("duckdns")
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	next := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	c.mu.Lock()
	c.status.NextRun = next
	c.status.Success = true
	c.status.Message = "preserve me"
	c.mu.Unlock()

	unrelatedValue := *cfg
	unrelated := &unrelatedValue
	unrelated.System.Hostname = "unrelated-system-change"
	if err := c.Apply(context.Background(), unrelated); err != nil {
		t.Fatal(err)
	}
	if got := c.Status(); !got.NextRun.Equal(next) || !got.Success || got.Message != "preserve me" {
		t.Fatalf("identical DDNS Apply erased runtime state: %+v", got)
	}

	changedValue := *unrelated
	changed := &changedValue
	changed.DDNS.Token = "new-token"
	if err := c.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	got := c.Status()
	if !got.NextRun.IsZero() || got.Success || got.Message != "" || !got.Enabled || got.Provider != "duckdns" || got.Hostname != cfg.DDNS.Hostname {
		t.Fatalf("changed DDNS did not reset schedule exactly: %+v", got)
	}
}

func TestTickFailureStatusMinimumIntervalAndLogging(t *testing.T) {
	logger := &captureLogger{}
	c := New(logger)
	now := time.Date(2026, 9, 1, 4, 5, 6, 0, time.UTC)
	c.Now = func() time.Time { return now }
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "", errors.New("address unavailable") }
	cfg := baseConfig("duckdns")
	cfg.DDNS.Interval = 1
	c.tick(context.Background(), cfg)
	got := c.Status()
	if got.Success || got.Address != "" || got.Message != "address unavailable" || !got.LastRun.Equal(now) || !got.NextRun.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected failure status: %+v", got)
	}
	if len(logger.warns) != 1 || len(logger.infos) != 0 {
		t.Fatalf("unexpected logs: infos=%v warns=%v", logger.infos, logger.warns)
	}
	c.tick(context.Background(), nil)
	disabledValue := *cfg
	disabled := &disabledValue
	disabled.DDNS.Enabled = false
	c.tick(context.Background(), disabled)
}

func TestTickSuccessLogs(t *testing.T) {
	logger := &captureLogger{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("OK")) }))
	defer server.Close()
	c := New(logger)
	c.DuckEndpoint = server.URL
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "203.0.113.1", nil }
	c.tick(context.Background(), baseConfig("duckdns"))
	if len(logger.infos) != 1 || len(logger.warns) != 0 {
		t.Fatalf("unexpected logs: infos=%v warns=%v", logger.infos, logger.warns)
	}
}

func TestStaleProviderResponseCannotOverwriteNewConfiguration(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	logger := &captureLogger{}
	c := New(logger)
	c.DuckEndpoint = server.URL
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "203.0.113.10", nil }
	old := baseConfig("duckdns")
	if err := c.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c.tick(context.Background(), old); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider request did not start")
	}
	newConfigValue := *old
	newConfig := &newConfigValue
	newConfig.DDNS.Hostname = "new.example.test"
	newConfig.DDNS.Token = "new-token"
	if err := c.Apply(context.Background(), newConfig); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old provider request did not finish")
	}
	got := c.Status()
	if got.Hostname != "new.example.test" || !got.LastRun.IsZero() || !got.NextRun.IsZero() || got.Success {
		t.Fatalf("stale response overwrote new configuration: %+v", got)
	}
	if len(logger.infos) != 0 || len(logger.warns) != 0 {
		t.Fatalf("stale response was logged: infos=%v warns=%v", logger.infos, logger.warns)
	}
}

func TestRunTicksAndStops(t *testing.T) {
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case called <- struct{}{}:
		default:
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	c := New(nil)
	c.DuckEndpoint = server.URL
	c.TickInterval = time.Millisecond
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "203.0.113.2", nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, func() *config.Config { return baseConfig("duckdns") }); close(done) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("Run did not tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestResolveWebResponseBoundariesAndHTTPFailures(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want string
	}{
		{"canonical ipv4", http.StatusOK, " 203.0.113.9\n", "203.0.113.9"},
		{"http failure", http.StatusBadGateway, "down", ""},
		{"oversized", http.StatusOK, strings.Repeat("1", 129), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.code); _, _ = w.Write([]byte(tc.body)) }))
			defer server.Close()
			c := New(nil)
			c.AddressEndpoint = server.URL
			got, err := c.resolveAddress(context.Background(), baseConfig("duckdns"))
			if tc.want == "" && err == nil {
				t.Fatalf("expected failure, got %q", got)
			}
			if tc.want != "" && (err != nil || got != tc.want) {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestResolveInterfaceFailures(t *testing.T) {
	c := New(nil)
	cfg := baseConfig("duckdns")
	cfg.DDNS.AddressSource = "interface"
	cfg.DDNS.WAN = "missing"
	if _, err := c.resolveAddress(context.Background(), cfg); err == nil {
		t.Fatal("missing WAN/interface was accepted")
	}
}

func TestResolveDirectAndPPPInterfaceAddressMatrix(t *testing.T) {
	tests := []struct {
		name, proto, wantName string
		addrs                 []string
		lookupErr             error
		want                  string
	}{
		{"direct", "dhcp", "eth-qa", []string{"broken", "2001:db8::1/64", "192.0.2.8/24"}, nil, "192.0.2.8"},
		{"pppoe", "pppoe", "ppp-wan-qa", []string{"198.51.100.4/32"}, nil, "198.51.100.4"},
		{"l2tp", "l2tp", "ppp-wan-qa", []string{"203.0.113.6/32"}, nil, "203.0.113.6"},
		{"lookup error", "static", "eth-qa", nil, errors.New("lookup failed"), ""},
		{"no ipv4", "static", "eth-qa", []string{"bad", "2001:db8::1/64"}, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig("duckdns")
			cfg.DDNS.AddressSource = "interface"
			cfg.DDNS.WAN = "wan-qa"
			cfg.Interfaces = []config.Interface{{ID: "if-qa", Name: "eth-qa"}}
			cfg.WANs = []config.WAN{{ID: "wan-qa", Interface: "if-qa", Proto: tc.proto}}
			c := New(nil)
			c.InterfaceAddrs = func(name string) ([]net.Addr, error) {
				if name != tc.wantName {
					t.Fatalf("lookup name=%q want=%q", name, tc.wantName)
				}
				if tc.lookupErr != nil {
					return nil, tc.lookupErr
				}
				result := make([]net.Addr, 0, len(tc.addrs))
				for _, address := range tc.addrs {
					result = append(result, testAddr(address))
				}
				return result, nil
			}
			got, err := c.resolveAddress(context.Background(), cfg)
			if tc.want == "" && err == nil {
				t.Fatalf("expected error, got %q", got)
			}
			if tc.want != "" && (err != nil || got != tc.want) {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestValidIPv4RejectsIPv6AndCanonicalizes(t *testing.T) {
	if _, err := validIPv4("2001:db8::1"); err == nil {
		t.Fatal("IPv6 was accepted")
	}
	if got, err := validIPv4("192.0.2.7"); err != nil || got != "192.0.2.7" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestProviderResponseMatrix(t *testing.T) {
	tests := []struct {
		name, provider, body string
		code                 int
		ok                   bool
	}{
		{"duck ok", "duckdns", "OK", 200, true},
		{"duck rejected", "duckdns", "KO", 200, false},
		{"cloud malformed", "cloudflare", "not-json", 200, false},
		{"noip unchanged", "noip", "nochg 192.0.2.1", 200, true},
		{"http error", "duckdns", "OK", 429, false},
		{"oversized", "noip", "good " + strings.Repeat("1", 4096), 200, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.code); _, _ = w.Write([]byte(tc.body)) }))
			defer server.Close()
			c := New(nil)
			c.DuckEndpoint, c.CloudEndpoint, c.NoIPEndpoint = server.URL, server.URL, server.URL
			err := c.update(context.Background(), baseConfig(tc.provider).DDNS, "192.0.2.1")
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && err == nil {
				t.Fatal("failure response was accepted")
			}
		})
	}
	if err := New(nil).update(context.Background(), baseConfig("unknown").DDNS, "192.0.2.1"); err == nil {
		t.Fatal("unknown provider was accepted")
	}
}

func TestNoIPDoesNotSendDuplicateForUnchangedAddress(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("good 192.0.2.1"))
	}))
	defer server.Close()
	c := New(nil)
	c.NoIPEndpoint = server.URL
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "192.0.2.1", nil }
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	cfg := baseConfig("noip")
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background(), cfg)
	first := c.Status()
	now = now.Add(time.Minute)
	c.tick(context.Background(), cfg)
	second := c.Status()
	if calls != 1 || !second.LastRun.Equal(first.LastRun) || !second.NextRun.Equal(now.Add(time.Minute)) {
		t.Fatalf("unchanged address caused provider update: calls=%d first=%+v second=%+v", calls, first, second)
	}
}

func TestNoIPPermanentFailureSuspendsUntilConfigurationChanges(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("badauth"))
	}))
	defer server.Close()
	c := New(nil)
	c.NoIPEndpoint = server.URL
	c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "192.0.2.1", nil }
	cfg := baseConfig("noip")
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background(), cfg)
	c.tick(context.Background(), cfg)
	if got := c.Status(); calls != 1 || !got.NextRun.IsZero() || got.Success || !strings.Contains(got.Message, "badauth") {
		t.Fatalf("permanent failure was retried: calls=%d status=%+v", calls, got)
	}
	changedValue := *cfg
	changed := &changedValue
	changed.DDNS.Password = "corrected"
	if err := c.Apply(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	c.tick(context.Background(), changed)
	if calls != 2 {
		t.Fatalf("configuration change did not resume updates: calls=%d", calls)
	}
}

func TestNoIPTemporaryFailuresBackOffThirtyMinutes(t *testing.T) {
	tests := []struct {
		name, body string
		code       int
	}{
		{"protocol 911", "911", http.StatusOK},
		{"http 500 with oversized body", strings.Repeat("failure", 1000), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			c := New(nil)
			c.NoIPEndpoint = server.URL
			c.ResolveAddress = func(context.Context, *config.Config) (string, error) { return "192.0.2.1", nil }
			now := time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
			c.Now = func() time.Time { return now }
			cfg := baseConfig("noip")
			if err := c.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			c.tick(context.Background(), cfg)
			if got := c.Status(); !got.NextRun.Equal(now.Add(30 * time.Minute)) {
				t.Fatalf("status=%+v", got)
			}
			now = now.Add(29 * time.Minute)
			c.tick(context.Background(), cfg)
			if calls != 1 {
				t.Fatalf("retried too early: %d", calls)
			}
			now = now.Add(time.Minute)
			c.tick(context.Background(), cfg)
			if calls != 2 {
				t.Fatalf("did not retry after backoff: %d", calls)
			}
		})
	}
}

func TestNoIPNon500HTTPFailureSuspends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	c := New(nil)
	c.NoIPEndpoint = server.URL
	err := c.update(context.Background(), baseConfig("noip").DDNS, "192.0.2.1")
	var providerFailure *providerError
	if !errors.As(err, &providerFailure) || !providerFailure.suspend {
		t.Fatalf("error=%#v", err)
	}
}

func TestReadLimitedExactLimitOverflowAndError(t *testing.T) {
	if got, err := readLimited(strings.NewReader("1234"), 4); err != nil || string(got) != "1234" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := readLimited(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("overflow was accepted")
	}
	if _, err := readLimited(failingReader{}, 4); err == nil {
		t.Fatal("read error was ignored")
	}
}

func TestHealthAndIdentity(t *testing.T) {
	c := New(nil)
	if c.Name() != "ddns" {
		t.Fatalf("name=%q", c.Name())
	}
	if err := c.Health(context.Background(), baseConfig("duckdns")); err != nil {
		t.Fatal(err)
	}
	if got := c.Status(); got != (Status{}) {
		t.Fatalf("initial status=%+v", got)
	}
}

func TestHTTPClientFailureIsReported(t *testing.T) {
	c := New(nil)
	c.DuckEndpoint = "http://127.0.0.1:1"
	c.Client = &http.Client{Timeout: 100 * time.Millisecond}
	if err := c.update(context.Background(), baseConfig("duckdns").DDNS, "192.0.2.1"); err == nil {
		t.Fatal("network failure was ignored")
	}
	c.AddressEndpoint = "http://127.0.0.1:1"
	if _, err := c.resolveAddress(context.Background(), baseConfig("duckdns")); err == nil {
		t.Fatal("address service failure was ignored")
	}
}

var _ io.Reader = failingReader{}
