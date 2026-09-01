package services

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestParseBlocklistSupportedFormatsAndDeduplicates(t *testing.T) {
	input := strings.Join([]string{
		"# comment",
		"! adblock comment",
		"example.com",
		"0.0.0.0 ads.example.com ads2.example.com # hosts comment",
		"127.0.0.1 example.com",
		":: trackers.example.org",
		"||telemetry.example.net^$third-party",
		"@@||allowed.example^",
		"localhost",
		"bad_domain.example",
		"192.0.2.1",
	}, "\n")
	domains, err := parseBlocklist([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example.com", "ads2.example.com", "example.com", "telemetry.example.net", "trackers.example.org"}
	if strings.Join(domains, ",") != strings.Join(want, ",") {
		t.Fatalf("domains=%v want=%v", domains, want)
	}
}

func TestParseBlocklistRejectsEmptyAndOversizedLine(t *testing.T) {
	if _, err := parseBlocklist([]byte("# comments only\ninvalid_domain\n")); err == nil {
		t.Fatal("empty effective list accepted")
	}
	if _, err := parseBlocklist([]byte(strings.Repeat("a", maxBlocklistLine+1))); err == nil {
		t.Fatal("oversized line accepted")
	}
}

func TestFetchBlocklistHTTPStatusLimitAndRedirectPolicy(t *testing.T) {
	oldFactory := newBlocklistHTTPClient
	t.Cleanup(func() { newBlocklistHTTPClient = oldFactory })
	responseStatus := http.StatusOK
	responseBody := []byte("ads.example\n")
	redirect := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		w.WriteHeader(responseStatus)
		_, _ = w.Write(responseBody)
	}))
	defer server.Close()
	newBlocklistHTTPClient = func(check func(*http.Request, []*http.Request) error) *http.Client {
		client := server.Client()
		client.CheckRedirect = check
		return client
	}
	if data, err := fetchBlocklist(context.Background(), server.URL); err != nil || string(data) != string(responseBody) {
		t.Fatalf("success data=%q err=%v", data, err)
	}
	responseStatus = http.StatusBadGateway
	if _, err := fetchBlocklist(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("HTTP failure=%v", err)
	}
	responseStatus = http.StatusOK
	responseBody = bytes.Repeat([]byte{'x'}, maxBlocklistBytes+1)
	if _, err := fetchBlocklist(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("size failure=%v", err)
	}
	responseBody = nil
	redirect = "http://insecure.example/list"
	if _, err := fetchBlocklist(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("redirect failure=%v", err)
	}
}

func TestBlocklistProviderRendersExactDomains(t *testing.T) {
	domains := []string{"ads.example", "track.example"}
	for name, output := range map[string]string{
		"dnsmasq":  string(renderDnsmasqBlocklist(domains)),
		"unbound":  string(renderUnboundBlocklist(domains)),
		"dnsproxy": string(renderDnsproxyBlocklist(domains)),
	} {
		for _, domain := range domains {
			if !strings.Contains(output, domain) {
				t.Errorf("%s missing %s: %s", name, domain, output)
			}
		}
	}
}

func blocklistTestConfig(provider string) *config.Config {
	cfg := providerTestConfig()
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = provider
	cfg.DNS.Port = 5353
	cfg.DNS.Blocklists = []config.Blocklist{{
		ID: "ads", Name: "Ads", URL: "https://lists.example/ads", Enabled: true,
	}}
	return cfg
}

func TestDNSBlocklistLifecycleAllProviders(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "unbound", "dnsproxy"} {
		t.Run(provider, func(t *testing.T) {
			useProviderPaths(t)
			r := newProviderRunner()
			m := NewManager(r)
			m.Resolv.Root = t.TempDir()
			content := []byte("0.0.0.0 ads.example\n||track.example^\n")
			m.Blocklist.Fetch = func(context.Context, string) ([]byte, error) { return content, nil }
			cfg := blocklistTestConfig(provider)
			s := NewDNS(m)
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			target := map[string]string{"dnsmasq": dnsmasqBlocklistPath, "unbound": unboundBlocklistPath, "dnsproxy": dnsproxyBlocklistPath}[provider]
			data, err := os.ReadFile(target)
			if err != nil || !strings.Contains(string(data), "ads.example") || !strings.Contains(string(data), "track.example") {
				t.Fatalf("provider file=%q err=%v", data, err)
			}
			cacheInfo, err := os.Stat(blocklistCachePath(cfg.DNS.Blocklists[0].URL))
			if err != nil || (runtime.GOOS != "windows" && cacheInfo.Mode().Perm() != 0o600) {
				t.Fatalf("cache info=%v err=%v", cacheInfo, err)
			}
			mainConfig := map[string]string{"dnsmasq": dnsmasqConfPath, "unbound": unboundConfPath, "dnsproxy": dnsproxyConfPath}[provider]
			mainData, err := os.ReadFile(mainConfig)
			if err != nil || !strings.Contains(string(mainData), filepath.Base(target)) {
				t.Fatalf("main config does not reference blocklist %s: %q err=%v", target, mainData, err)
			}

			r.commands = nil
			content = []byte("new.example\n")
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			unit := map[string]string{"dnsmasq": dnsmasqUnit, "unbound": unboundUnit, "dnsproxy": dnsproxyUnit}[provider]
			if !hasCommand(r.commands, "systemctl restart "+unit) {
				t.Fatalf("blocklist content change did not restart %s: %v", provider, r.commands)
			}
			data, _ = os.ReadFile(target)
			if !strings.Contains(string(data), "new.example") || strings.Contains(string(data), "ads.example") {
				t.Fatalf("updated provider file=%q", data)
			}
		})
	}
}

func TestDNSBlocklistUsesCacheOnFetchFailure(t *testing.T) {
	useProviderPaths(t)
	m := NewBlocklistManager()
	cfg := blocklistTestConfig("dnsmasq")
	m.Fetch = func(context.Context, string) ([]byte, error) { return []byte("cached.example\n"), nil }
	if _, tx, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	} else if tx == nil {
		t.Fatal("missing transaction")
	}
	m.Fetch = func(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("network down") }
	if _, _, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("working cache was not used: %v", err)
	}
	data, err := os.ReadFile(dnsmasqBlocklistPath)
	if err != nil || !strings.Contains(string(data), "cached.example") {
		t.Fatalf("provider file=%q err=%v", data, err)
	}
}

func TestDNSBlocklistFailureRestoresProviderAndCacheBytes(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	cfg := blocklistTestConfig("dnsmasq")
	content := []byte("old.example\n")
	m.Blocklist.Fetch = func(context.Context, string) ([]byte, error) { return content, nil }
	s := NewDNS(m)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	providerBefore, _ := os.ReadFile(dnsmasqBlocklistPath)
	cachePath := blocklistCachePath(cfg.DNS.Blocklists[0].URL)
	cacheBefore, _ := os.ReadFile(cachePath)
	content = []byte("new.example\n")
	r.failName = "dnsmasq"
	if err := s.Apply(context.Background(), cfg); err == nil {
		t.Fatal("injected provider validation failure was accepted")
	}
	providerAfter, _ := os.ReadFile(dnsmasqBlocklistPath)
	cacheAfter, _ := os.ReadFile(cachePath)
	if string(providerAfter) != string(providerBefore) || string(cacheAfter) != string(cacheBefore) {
		t.Fatalf("rollback mismatch provider=%q/%q cache=%q/%q", providerBefore, providerAfter, cacheBefore, cacheAfter)
	}
}

func TestDNSBlocklistFreshFetchFailureDoesNotTouchWorkingFile(t *testing.T) {
	useProviderPaths(t)
	if err := os.WriteFile(dnsmasqBlocklistPath, []byte("working-bytes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := NewBlocklistManager()
	m.Fetch = func(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("network down") }
	cfg := blocklistTestConfig("dnsmasq")
	if _, _, err := m.Apply(context.Background(), cfg); err == nil {
		t.Fatal("fresh fetch failure accepted")
	}
	data, err := os.ReadFile(dnsmasqBlocklistPath)
	info, statErr := os.Stat(dnsmasqBlocklistPath)
	if err != nil || statErr != nil || string(data) != "working-bytes\n" || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o640) {
		t.Fatalf("working file changed data=%q mode=%v err=%v statErr=%v", data, info.Mode(), err, statErr)
	}
	if _, err := os.Stat(filepath.Join(blocklistCacheDir, "unexpected")); err == nil {
		t.Fatal("unexpected cache artifact")
	}
}

func TestDNSBlocklistDisableCleansFilesAndHealthDetectsDrift(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	m.Blocklist.Fetch = func(context.Context, string) ([]byte, error) { return []byte("ads.example\n"), nil }
	cfg := blocklistTestConfig("dnsmasq")
	s := NewDNS(m)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dnsmasqBlocklistPath, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupt provider blocklist passed Health")
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) == 0 || actions[0].Kind != "repair" {
		t.Fatalf("drift plan=%#v err=%v", actions, err)
	}
	// Repair first, then disable only the list while keeping DNS itself alive.
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	off := *cfg
	off.DNS = cfg.DNS
	off.DNS.Blocklists = append([]config.Blocklist(nil), cfg.DNS.Blocklists...)
	off.DNS.Blocklists[0].Enabled = false
	if err := s.Apply(context.Background(), &off); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale blocklist %s: %v", path, err)
		}
	}
	if err := s.Health(context.Background(), &off); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(cfg, &off); err != nil || len(actions) == 0 || actions[0].Target != "DNS blocklists" {
		t.Fatalf("disable plan=%#v err=%v", actions, err)
	}
}
