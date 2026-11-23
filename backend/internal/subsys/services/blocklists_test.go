package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestFetchBlocklistTrustsConfiguredPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ads.private.example\n"))
	}))
	defer server.Close()

	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "private-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := fetchBlocklistWithCA(context.Background(), server.URL, caFile)
	if err != nil {
		t.Fatalf("private CA fetch failed: %v", err)
	}
	if string(data) != "ads.private.example\n" {
		t.Fatalf("data=%q", data)
	}
}

// Файл центра сертификации задаётся путём в панели. Читается только
// обычный файл ограниченного размера, иначе netosd читал бы без предела.
func TestBlocklistCAFileIsBoundedRegularFile(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ads.private.example\n"))
	}))
	defer server.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})

	oversized := filepath.Join(t.TempDir(), "oversized-ca.pem")
	padding := bytes.Repeat([]byte("#\n"), maxBlocklistCABytes/2+1)
	if err := os.WriteFile(oversized, append(caPEM, padding...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchBlocklistWithCA(context.Background(), server.URL, oversized); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("файл больше предела принят: %v", err)
	}

	if _, err := fetchBlocklistWithCA(context.Background(), server.URL, t.TempDir()); err == nil || !strings.Contains(err.Error(), "не является обычным файлом") {
		t.Fatalf("каталог принят как файл CA: %v", err)
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
			m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) { return content, nil }
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
	m.Fetch = func(context.Context, string, string) ([]byte, error) { return []byte("cached.example\n"), nil }
	if _, tx, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	} else if tx == nil {
		t.Fatal("missing transaction")
	}
	m.Fetch = func(context.Context, string, string) ([]byte, error) { return nil, fmt.Errorf("network down") }
	if _, _, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("working cache was not used: %v", err)
	}
	data, err := os.ReadFile(dnsmasqBlocklistPath)
	if err != nil || !strings.Contains(string(data), "cached.example") {
		t.Fatalf("provider file=%q err=%v", data, err)
	}
	statuses, err := ReadBlocklistStatuses()
	if err != nil {
		t.Fatal(err)
	}
	status := statuses[cfg.DNS.Blocklists[0].URL]
	if status.Source != "cache" || !strings.Contains(status.Error, "network down") {
		t.Fatalf("source status=%+v", status)
	}
}

func TestBlocklistRewritesOnlyChangedCacheAndStatus(t *testing.T) {
	useProviderPaths(t)
	cfg := blocklistTestConfig("dnsmasq")
	first := cfg.DNS.Blocklists[0].URL
	second := "https://lists.example/second"
	cfg.DNS.Blocklists = append(cfg.DNS.Blocklists, config.Blocklist{URL: second, Enabled: true})
	m := NewBlocklistManager()
	content := "ads.example\n"
	var fetchErr error
	m.Fetch = func(_ context.Context, url, _ string) ([]byte, error) {
		if url == first {
			return []byte(content), fetchErr
		}
		return []byte("second.example\n"), nil
	}
	apply := func() {
		t.Helper()
		if _, _, err := m.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	paths := []string{blocklistCachePath(first), blocklistCachePath(second), blocklistStatusPath()}
	stamp := time.Unix(1000000000, 0)
	check := func(written ...bool) {
		t.Helper()
		for _, path := range paths {
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		apply()
		for i, path := range paths {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := !info.ModTime().Equal(stamp); got != written[i] {
				t.Errorf("%s: written=%v, want %v", filepath.Base(path), got, written[i])
			}
		}
	}
	check(false, false, false)
	content = "new.example\n"
	check(true, false, false)
	fetchErr = errors.New("offline")
	check(false, false, true)
	check(false, false, false)
	fetchErr = nil
	check(false, false, true)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(paths[0], 0o644); err != nil {
			t.Fatal(err)
		}
		check(true, false, false)
		info, err := os.Stat(paths[0])
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("cache permissions: %v, %v", info, err)
		}
	}
}

func TestBlocklistProviderChangeAfterSnapshot(t *testing.T) {
	useProviderPaths(t)
	m := NewBlocklistManager()
	cfg := blocklistTestConfig("dnsmasq")
	content := []byte("ads.example\n")
	m.Fetch = func(context.Context, string, string) ([]byte, error) { return content, nil }
	apply := func(wantChanged bool) {
		t.Helper()
		changed, _, err := m.Apply(context.Background(), cfg)
		if err != nil || changed != wantChanged {
			t.Fatalf("changed=%v, want %v, error=%v", changed, wantChanged, err)
		}
	}
	apply(true)
	m.Fetch = func(context.Context, string, string) ([]byte, error) {
		if err := os.WriteFile(dnsmasqBlocklistPath, []byte("drift"), 0o644); err != nil {
			t.Fatal(err)
		}
		return content, nil
	}
	apply(true)
	m.Fetch = func(context.Context, string, string) ([]byte, error) { return content, nil }
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dnsmasqBlocklistPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(dnsmasqBlocklistPath)
	if err != nil {
		t.Fatal(err)
	}
	apply(false)
	after, err := os.Stat(dnsmasqBlocklistPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("unchanged provider file replaced: %v", err)
	}
	if err := m.Health(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestDNSBlocklistRollbackOnSnapshotFailure(t *testing.T) {
	useProviderPaths(t)
	m := NewManager(newProviderRunner())
	m.Resolv.Root = t.TempDir()
	cfg := dnsDomainPolicyConfig("unbound")
	cfg.DNS.Blocklists = blocklistTestConfig("unbound").DNS.Blocklists
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) {
		return []byte("ads.example\n"), nil
	}
	if err := os.MkdirAll(dnsmasqConfPath, 0o700); err != nil {
		t.Fatal(err)
	}
	dns := NewDNS(m)
	if err := dns.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), dnsmasqConfPath) {
		t.Fatalf("expected snapshot failure for %s: %v", dnsmasqConfPath, err)
	}
	for _, path := range []string{unboundBlocklistPath, blocklistCachePath(cfg.DNS.Blocklists[0].URL), blocklistStatusPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("failed apply left %s: %v", path, err)
		}
	}
	if err := os.Remove(dnsmasqConfPath); err != nil {
		t.Fatal(err)
	}
	if err := dns.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("retry: %v", err)
	}
	data, err := os.ReadFile(unboundBlocklistPath)
	if err != nil || !bytes.Contains(data, []byte("ads.example")) {
		t.Fatalf("retry did not publish blocklist: %q, %v", data, err)
	}
}

func TestDNSBlocklistFailureRestoresProviderAndCacheBytes(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	cfg := blocklistTestConfig("dnsmasq")
	content := []byte("old.example\n")
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) { return content, nil }
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

func TestDNSBlocklistApplyReportsFailedFileRollback(t *testing.T) {
	useProviderPaths(t)
	cfg := blocklistTestConfig("dnsmasq")
	m := NewManager(newProviderRunner())
	m.Resolv.Root = t.TempDir()
	dns := NewDNS(m)
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) {
		return []byte("old.example\n"), nil
	}
	ctx := context.Background()
	if err := dns.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	obstacle := filepath.Join(unboundBlocklistPath, "keep")
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) {
		if err := os.MkdirAll(unboundBlocklistPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(obstacle, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		return []byte("new.example\n"), nil
	}
	err := dns.Apply(ctx, cfg)
	var cause *os.PathError
	if !errors.As(err, &cause) || cause.Path != unboundBlocklistPath ||
		!strings.Contains(err.Error(), "возврат файлов blocklist: "+unboundBlocklistPath) {
		t.Fatalf("expected removal and rollback failures, got %v", err)
	}
	for _, path := range []string{dnsmasqBlocklistPath, blocklistCachePath(cfg.DNS.Blocklists[0].URL)} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(data, []byte("old.example")) || bytes.Contains(data, []byte("new.example")) {
			t.Fatalf("incomplete restore of %s: %q, %v", path, data, err)
		}
	}
	for _, path := range []string{obstacle, unboundBlocklistPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) {
		return []byte("new.example\n"), nil
	}
	if err := dns.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dnsmasqBlocklistPath)
	if err != nil || !bytes.Contains(data, []byte("new.example")) {
		t.Fatalf("retry: %q, %v", data, err)
	}
}

func TestDNSBlocklistFreshFetchFailureKeepsOtherSourcesAndReportsError(t *testing.T) {
	useProviderPaths(t)
	m := NewBlocklistManager()
	cfg := blocklistTestConfig("dnsmasq")
	goodURL := cfg.DNS.Blocklists[0].URL
	cfg.DNS.Blocklists = append(cfg.DNS.Blocklists, config.Blocklist{ID: "missing", Name: "Missing", URL: "https://lists.example/missing", Enabled: true})
	m.Fetch = func(_ context.Context, url, _ string) ([]byte, error) {
		if url == goodURL {
			return []byte("working.example\n"), nil
		}
		return nil, fmt.Errorf("HTTP 404")
	}
	if _, _, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("unavailable source broke DNS apply: %v", err)
	}
	data, err := os.ReadFile(dnsmasqBlocklistPath)
	if err != nil || !strings.Contains(string(data), "working.example") {
		t.Fatalf("working source lost: %q, %v", data, err)
	}
	statuses, err := ReadBlocklistStatuses()
	if err != nil || statuses[cfg.DNS.Blocklists[1].URL].Source != "unavailable" || !strings.Contains(statuses[cfg.DNS.Blocklists[1].URL].Error, "HTTP 404") {
		t.Fatalf("missing error status: %+v, %v", statuses, err)
	}
	if err := m.Health(cfg); err != nil {
		t.Fatalf("unavailable source failed health: %v", err)
	}
	m.Fetch = func(context.Context, string, string) ([]byte, error) { return []byte("recovered.example\n"), nil }
	if _, _, err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	statuses, err = ReadBlocklistStatuses()
	if err != nil || statuses[cfg.DNS.Blocklists[1].URL].Source != "fetched" {
		t.Fatalf("source did not recover: %v, %v", statuses, err)
	}
	if err := m.Health(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestDNSBlocklistDisableCleansFilesAndHealthDetectsDrift(t *testing.T) {
	useProviderPaths(t)
	r := newProviderRunner()
	m := NewManager(r)
	m.Resolv.Root = t.TempDir()
	m.Blocklist.Fetch = func(context.Context, string, string) ([]byte, error) { return []byte("ads.example\n"), nil }
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
