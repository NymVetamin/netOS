//go:build linux

package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Cache parsed certificates, never connections or probe results. Inspect the
// trust files on every probe so updates/removals take effect without a restart.
type probeTrust struct {
	mu    sync.Mutex
	files map[string]os.FileInfo
	pool  *x509.CertPool
}

var httpProbeTrust probeTrust

func (c *probeTrust) roots(dir string) (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make(map[string]os.FileInfo)
	changed := c.pool == nil
	for _, entry := range entries {
		// Match curl/OpenSSL's bundle and hashed CA directory. Arbitrary PEM
		// files (for example a snakeoil server certificate) are not trust anchors.
		if !probeCAFile(entry.Name()) {
			continue
		}
		name := filepath.Join(dir, entry.Name())
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		files[name] = info
		old := c.files[name]
		if old == nil || !os.SameFile(old, info) || old.Size() != info.Size() || !old.ModTime().Equal(info.ModTime()) {
			changed = true
		}
	}
	if len(files) != len(c.files) {
		changed = true
	}
	if !changed {
		return c.pool, nil
	}
	pool := x509.NewCertPool()
	for name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(data)
	}
	c.files, c.pool = files, pool
	return pool, nil
}

func probeCAFile(name string) bool {
	if name == "ca-certificates.crt" {
		return true
	}
	hash, suffix, ok := strings.Cut(name, ".")
	if !ok || len(hash) != 8 || suffix == "" {
		return false
	}
	for _, ch := range hash {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	for _, ch := range suffix {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// Preserve explicit curl customization via the original implementation. The
// native path is for ordinary router HTTP(S) checks on the Debian trust store.
func nativeHTTPProbeAllowed(target string) bool {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return false
	}
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME"} {
		if os.Getenv(key) != "" {
			return false
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// System services commonly have no HOME. curl also consults passwd.
		account, lookupErr := user.Current()
		if lookupErr != nil || account.HomeDir == "" {
			return false
		}
		home = account.HomeDir
	}
	for _, name := range []string{filepath.Join(home, ".curlrc"), filepath.Join(home, ".config", "curlrc")} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (e *Exec) ProbeHTTP(ctx context.Context, iface, target string, timeout time.Duration) error {
	if !nativeHTTPProbeAllowed(target) {
		return curlProbeHTTP(ctx, e, iface, target, timeout)
	}
	limit := e.Timeout
	if limit <= 0 {
		limit = 30 * time.Second
	}
	if timeout > 0 && timeout < limit {
		limit = timeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var roots *x509.CertPool
	if u, _ := url.Parse(target); u.Scheme == "https" {
		var err error
		roots, err = httpProbeTrust.roots("/etc/ssl/certs")
		if err != nil {
			return curlProbeHTTP(ctx, e, iface, target, timeout)
		}
	}
	return nativeHTTPProbe(ctx, iface, target, roots)
}

func nativeHTTPProbe(ctx context.Context, iface, target string, roots *x509.CertPool) error {
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		if iface == "" {
			return nil
		}
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "netOS health probe")
	req.Header.Set("Accept", "*/*")
	// RoundTrip never follows or parses Location, including malformed redirects.
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP probe: %s", resp.Status)
	}
	// A TUN can accept TCP locally. Require the complete application response,
	// including body errors/timeouts, just as curl does without --head.
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}
