package services

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const (
	maxBlocklistBytes   = 16 << 20
	maxBlocklistLine    = 1 << 20
	maxBlocklistDomains = 500_000
)

var (
	blocklistCacheDir       = "/var/lib/netos/blocklists"
	dnsmasqBlocklistPath    = "/var/lib/netos/generated/dnsmasq-blocklist.conf"
	unboundBlocklistPath    = "/var/lib/netos/generated/unbound-blocklist.conf"
	dnsproxyBlocklistPath   = "/var/lib/netos/generated/dnsproxy-blocklist.hosts"
	defaultBlocklistFetcher = fetchBlocklistWithCA
	newBlocklistHTTPClient  = func(checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
		return &http.Client{Timeout: 30 * time.Second, CheckRedirect: checkRedirect}
	}
)

type BlocklistSourceStatus struct {
	Source string `json:"source"`
	Error  string `json:"error,omitempty"`
}

func blocklistStatusPath() string { return filepath.Join(blocklistCacheDir, "status.json") }

func ReadBlocklistStatuses() (map[string]BlocklistSourceStatus, error) {
	data, err := os.ReadFile(blocklistStatusPath())
	if os.IsNotExist(err) {
		return map[string]BlocklistSourceStatus{}, nil
	}
	if err != nil {
		return nil, err
	}
	var statuses map[string]BlocklistSourceStatus
	if err := json.Unmarshal(data, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

type BlocklistManager struct {
	Fetch func(context.Context, string, string) ([]byte, error)
}

func NewBlocklistManager() *BlocklistManager {
	return &BlocklistManager{Fetch: defaultBlocklistFetcher}
}

func hasEnabledBlocklists(cfg *config.Config) bool {
	if cfg == nil || !cfg.DNS.Enabled {
		return false
	}
	for _, item := range cfg.DNS.Blocklists {
		if item.Enabled {
			return true
		}
	}
	return false
}

func fetchBlocklist(ctx context.Context, rawURL string) ([]byte, error) {
	return fetchBlocklistWithCA(ctx, rawURL, "")
}

func fetchBlocklistWithCA(ctx context.Context, rawURL, caFile string) ([]byte, error) {
	if err := validateBlocklistURL(rawURL); err != nil {
		return nil, err
	}
	client := newBlocklistHTTPClient(func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("слишком много перенаправлений")
		}
		return validateBlocklistURL(req.URL.String())
	})
	if caFile != "" {
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("центр сертификации %s: %w", caFile, err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("центр сертификации %s: PEM не содержит сертификатов", caFile)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		client.Transport = transport
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netOS-blocklist/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBlocklistBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBlocklistBytes {
		return nil, fmt.Errorf("список больше %d MiB", maxBlocklistBytes>>20)
	}
	return data, nil
}

func validateBlocklistURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("нужен безопасный HTTPS URL без учётных данных и фрагмента")
	}
	return nil
}

func parseBlocklist(data []byte) ([]string, error) {
	domains := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxBlocklistLine)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "[") {
			continue
		}
		if before, _, found := strings.Cut(line, "#"); found {
			line = strings.TrimSpace(before)
		}
		var candidates []string
		if strings.HasPrefix(line, "||") {
			domain := strings.TrimPrefix(line, "||")
			if before, _, found := strings.Cut(domain, "^"); found {
				domain = before
			}
			candidates = []string{domain}
		} else {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if _, err := netip.ParseAddr(fields[0]); err == nil {
				candidates = fields[1:]
			} else if len(fields) == 1 {
				candidates = fields
			} else {
				continue
			}
		}
		for _, candidate := range candidates {
			domain := strings.ToLower(strings.Trim(strings.TrimSpace(candidate), "."))
			if domain == "localhost" || domain == "localhost.localdomain" || domain == "local" {
				continue
			}
			if !validBlockDomain(domain) {
				continue
			}
			domains[domain] = struct{}{}
			if len(domains) > maxBlocklistDomains {
				return nil, fmt.Errorf("список содержит больше %d уникальных доменов", maxBlocklistDomains)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("строка %d: %w", lineNumber+1, err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("список не содержит ни одного корректного домена")
	}
	out := make([]string, 0, len(domains))
	for domain := range domains {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

func validBlockDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func canonicalDomainFile(domains []string) []byte {
	if len(domains) == 0 {
		return nil
	}
	return []byte(strings.Join(domains, "\n") + "\n")
}

func blocklistCachePath(rawURL string) string {
	hash := sha256.Sum256([]byte(rawURL))
	return filepath.Join(blocklistCacheDir, fmt.Sprintf("%x.domains", hash))
}

func (m *BlocklistManager) loadDomains(ctx context.Context, cfg *config.Config) ([]string, error) {
	all := map[string]struct{}{}
	statuses := map[string]BlocklistSourceStatus{}
	for _, item := range cfg.DNS.Blocklists {
		if !item.Enabled {
			continue
		}
		cachePath := blocklistCachePath(item.URL)
		data, fetchErr := m.Fetch(ctx, item.URL, item.CAFile)
		domains, parseErr := parseBlocklist(data)
		if fetchErr != nil || parseErr != nil {
			cause := fetchErr
			if cause == nil {
				cause = parseErr
			}
			cached, cacheErr := os.ReadFile(cachePath)
			if cacheErr != nil {
				statuses[item.URL] = BlocklistSourceStatus{Source: "unavailable", Error: fmt.Sprintf("%v; рабочего кэша нет", cause)}
				continue
			}
			domains, cacheErr = parseBlocklist(cached)
			if cacheErr != nil {
				statuses[item.URL] = BlocklistSourceStatus{Source: "unavailable", Error: fmt.Sprintf("%v; кэш повреждён: %v", cause, cacheErr)}
				continue
			}
			statuses[item.URL] = BlocklistSourceStatus{Source: "cache", Error: cause.Error()}
		} else {
			if err := system.WriteFileAtomic(cachePath, canonicalDomainFile(domains), 0o600); err != nil {
				return nil, fmt.Errorf("кэш списка %q: %w", item.Name, err)
			}
			statuses[item.URL] = BlocklistSourceStatus{Source: "fetched"}
		}
		for _, domain := range domains {
			all[domain] = struct{}{}
			if len(all) > maxBlocklistDomains {
				return nil, fmt.Errorf("включённые списки содержат больше %d уникальных доменов", maxBlocklistDomains)
			}
		}
	}
	out := make([]string, 0, len(all))
	for domain := range all {
		out = append(out, domain)
	}
	sort.Strings(out)
	encoded, err := json.Marshal(statuses)
	if err != nil {
		return nil, err
	}
	if err := system.WriteFileAtomic(blocklistStatusPath(), encoded, 0o600); err != nil {
		return nil, fmt.Errorf("статус DNS blocklist: %w", err)
	}
	return out, nil
}

func renderDnsmasqBlocklist(domains []string) []byte {
	var out strings.Builder
	out.WriteString("# Сгенерировано netOS. Не редактировать.\n")
	for _, domain := range domains {
		fmt.Fprintf(&out, "address=/%s/#\n", domain)
	}
	return []byte(out.String())
}

func renderUnboundBlocklist(domains []string) []byte {
	var out strings.Builder
	out.WriteString("# Сгенерировано netOS. Не редактировать.\n")
	for _, domain := range domains {
		fmt.Fprintf(&out, "local-zone: %q always_nxdomain\n", domain)
	}
	return []byte(out.String())
}

func renderDnsproxyBlocklist(domains []string) []byte {
	var out strings.Builder
	out.WriteString("# Сгенерировано netOS. Не редактировать.\n")
	for _, domain := range domains {
		fmt.Fprintf(&out, "0.0.0.0 %s\n:: %s\n", domain, domain)
	}
	return []byte(out.String())
}

type blocklistFileSnapshot struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

type blocklistTransaction struct {
	files []blocklistFileSnapshot
}

func snapshotBlocklistFiles(cfg *config.Config) (*blocklistTransaction, error) {
	tx := &blocklistTransaction{}
	paths := []string{dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath, blocklistStatusPath()}
	seen := map[string]bool{}
	if cfg != nil {
		for _, item := range cfg.DNS.Blocklists {
			if item.Enabled {
				paths = append(paths, blocklistCachePath(item.URL))
			}
		}
	}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		item := blocklistFileSnapshot{path: path}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			tx.files = append(tx.files, item)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s не является обычным файлом", path)
		}
		item.data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		item.exists = true
		item.mode = info.Mode().Perm()
		tx.files = append(tx.files, item)
	}
	return tx, nil
}

func (tx *blocklistTransaction) Rollback() error {
	if tx == nil {
		return nil
	}
	var failures []string
	for _, item := range tx.files {
		if item.exists {
			if err := system.WriteFileAtomic(item.path, item.data, item.mode); err != nil {
				failures = append(failures, item.path+": "+err.Error())
			}
		} else if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, item.path+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("возврат файлов blocklist: %s", strings.Join(failures, "; "))
	}
	return nil
}

func blocklistProviderFile(cfg *config.Config, domains []string) (string, []byte) {
	if !hasEnabledBlocklists(cfg) {
		return "", nil
	}
	switch cfg.DNS.Provider {
	case "dnsmasq":
		return dnsmasqBlocklistPath, renderDnsmasqBlocklist(domains)
	case "unbound":
		return unboundBlocklistPath, renderUnboundBlocklist(domains)
	case "dnsproxy":
		return dnsproxyBlocklistPath, renderDnsproxyBlocklist(domains)
	default:
		return "", nil
	}
}

// Apply downloads every enabled source before touching the provider file.
// It returns an exact byte snapshot that the DNS coordinator restores if
// preflight, daemon restart or resolver switching fails later in the apply.
func (m *BlocklistManager) Apply(ctx context.Context, cfg *config.Config) (bool, *blocklistTransaction, error) {
	if m == nil || m.Fetch == nil {
		return false, nil, fmt.Errorf("загрузчик DNS blocklist не настроен")
	}
	tx, err := snapshotBlocklistFiles(cfg)
	if err != nil {
		return false, nil, err
	}
	var domains []string
	if hasEnabledBlocklists(cfg) {
		domains, err = m.loadDomains(ctx, cfg)
		if err != nil {
			_ = tx.Rollback()
			return false, nil, err
		}
	} else if err := os.Remove(blocklistStatusPath()); err != nil && !os.IsNotExist(err) {
		_ = tx.Rollback()
		return false, nil, err
	}
	target, content := blocklistProviderFile(cfg, domains)
	changed := false
	for _, path := range []string{dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath} {
		if path == target {
			changed = system.FileChanged(path, content)
			if _, err := writeManagedFile(path, content, 0o644); err != nil {
				_ = tx.Rollback()
				return false, nil, err
			}
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			_ = tx.Rollback()
			return false, nil, err
		}
	}
	return changed, tx, nil
}

func (m *BlocklistManager) cachedDomains(cfg *config.Config) ([]string, error) {
	all := map[string]struct{}{}
	statuses, err := ReadBlocklistStatuses()
	if err != nil {
		return nil, err
	}
	for _, item := range cfg.DNS.Blocklists {
		if !item.Enabled {
			continue
		}
		if statuses[item.URL].Source == "unavailable" {
			continue
		}
		data, err := os.ReadFile(blocklistCachePath(item.URL))
		if err != nil {
			return nil, fmt.Errorf("кэш списка %q: %w", item.Name, err)
		}
		domains, err := parseBlocklist(data)
		if err != nil {
			return nil, fmt.Errorf("кэш списка %q: %w", item.Name, err)
		}
		for _, domain := range domains {
			all[domain] = struct{}{}
		}
	}
	out := make([]string, 0, len(all))
	for domain := range all {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

func (m *BlocklistManager) Health(cfg *config.Config) error {
	if m == nil {
		return fmt.Errorf("загрузчик DNS blocklist не настроен")
	}
	paths := []string{dnsmasqBlocklistPath, unboundBlocklistPath, dnsproxyBlocklistPath}
	if !hasEnabledBlocklists(cfg) {
		for _, path := range paths {
			if err := generatedAbsent(path); err != nil {
				return err
			}
		}
		return nil
	}
	domains, err := m.cachedDomains(cfg)
	if err != nil {
		return err
	}
	target, content := blocklistProviderFile(cfg, domains)
	for _, path := range paths {
		if path == target {
			if err := managedFileHealth(path, content, 0o644); err != nil {
				return err
			}
			continue
		}
		if err := generatedAbsent(path); err != nil {
			return err
		}
	}
	return nil
}
