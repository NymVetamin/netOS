// Package certificates manages server TLS independently of the web listener.
package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

type ACME interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	HTTPHandler(http.Handler) http.Handler
	TLSConfig() *tls.Config
}

type Factory func(cache, domain, email string) (ACME, error)

type Pair struct {
	Certificate []byte
	Key         []byte
	Leaf        *x509.Certificate
}

type Status struct {
	Domain      string    `json:"domain"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type Manager struct {
	Dir         string
	Factory     Factory
	Listen      func(string, string) (net.Listener, error)
	HTTPAddress string
	// PrepareHTTP opens only the ACME challenge path through the host firewall
	// while obtaining the first certificate, before the final ruleset is applied.
	PrepareHTTP   func(context.Context) (func(), error)
	op            sync.Mutex
	mu            sync.RWMutex
	issuers       map[string]ACME
	handlers      map[string]http.Handler
	status        map[string]Status
	httpServer    *http.Server
	httpFallback  http.Handler
	listenerError error
}

func New(dir string, factory Factory) *Manager {
	return &Manager{Dir: dir, Factory: factory, Listen: net.Listen, HTTPAddress: ":80", issuers: map[string]ACME{}, handlers: map[string]http.Handler{}, status: map[string]Status{}}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.httpServer != nil {
		return m.httpServer.Close()
	}
	return nil
}

func (m *Manager) HTTPActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.httpServer != nil && m.listenerError == nil
}

// SetHTTPFallback shares the HTTP listener with certificate challenges.
// A nil handler disables navigation without interrupting ACME renewal.
func (m *Manager) SetHTTPFallback(handler http.Handler) error {
	if handler != nil {
		if err := m.startHTTP(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.httpFallback = handler
	m.mu.Unlock()
	return nil
}

func (m *Manager) Status() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Status
	for _, s := range m.status {
		out = append(out, s)
	}
	return out
}

func hostname(value string) string { return strings.TrimSuffix(strings.ToLower(value), ".") }

func ParsePair(certPEM, keyPEM []byte, name string) (*Pair, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("сертификат и закрытый ключ не образуют пару")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("некорректный сертификат")
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, fmt.Errorf("сертификат вне срока действия")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
			}
		}
		if !serverAuth {
			return nil, fmt.Errorf("сертификат не предназначен для TLS-сервера")
		}
	}
	previous := leaf
	for _, der := range pair.Certificate[1:] {
		issuer, err := x509.ParseCertificate(der)
		if err != nil || time.Now().Before(issuer.NotBefore) || !time.Now().Before(issuer.NotAfter) {
			return nil, fmt.Errorf("некорректная или просроченная цепочка сертификатов")
		}
		if err := previous.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("цепочка сертификатов не соответствует серверному сертификату")
		}
		previous = issuer
	}
	if name != "" {
		if err := leaf.VerifyHostname(hostname(name)); err != nil {
			return nil, fmt.Errorf("сертификат не покрывает адрес %s", name)
		}
	}
	var chain []byte
	for _, der := range pair.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &Pair{Certificate: chain, Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), Leaf: leaf}, nil
}

func ReadPair(certFile, keyFile, name string) (*Pair, error) {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ParsePair(cert, key, name)
}

// Bundle publishes the chain and key together. Consumers can use the same PEM
// for both paths, avoiding a half-written certificate/key pair on disk.
func (p *Pair) Bundle() []byte { return append(append([]byte{}, p.Certificate...), p.Key...) }

func writePair(file string, pair *Pair) (bool, error) {
	data := pair.Bundle()
	if old, err := os.ReadFile(file); err == nil && string(old) == string(data) {
		return false, nil
	}
	return true, system.WriteFileAtomic(file, data, 0o600)
}

func (m *Manager) startHTTP() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.httpServer != nil {
		return m.listenerError
	}
	listener, err := m.Listen("tcp", m.HTTPAddress)
	if err != nil {
		return fmt.Errorf("порт HTTP-01 недоступен: %w", err)
	}
	m.httpServer = &http.Server{Handler: http.HandlerFunc(m.challenge), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		err := m.httpServer.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			m.mu.Lock()
			m.listenerError = err
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *Manager) challenge(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	m.mu.RLock()
	handler := m.handlers[hostname(host)]
	fallback := m.httpFallback
	m.mu.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") && fallback != nil {
		fallback.ServeHTTP(w, r)
		return
	}
	if handler == nil || !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		http.NotFound(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

func (m *Manager) acme(ctx context.Context, domain, email string) (*Pair, error) {
	domain = hostname(domain)
	m.mu.RLock()
	issuer := m.issuers[domain]
	m.mu.RUnlock()
	if issuer == nil {
		if m.Factory == nil {
			return nil, fmt.Errorf("ACME недоступен")
		}
		identity := strings.TrimSpace(email)
		if identity == "" {
			identity = "no-email"
		}
		digest := sha256.Sum256([]byte(identity))
		var err error
		issuer, err = m.Factory(filepath.Join(m.Dir, "acme", hex.EncodeToString(digest[:8])), domain, email)
		if err != nil {
			return nil, err
		}
		// HTTPHandler enables HTTP-01 inside autocert. It must be constructed
		// before GetCertificate, not lazily on the first challenge request.
		handler := issuer.HTTPHandler(http.NotFoundHandler())
		m.mu.Lock()
		m.issuers[domain] = issuer
		m.handlers[domain] = handler
		m.mu.Unlock()
	}
	if err := m.startHTTP(); err != nil {
		return nil, err
	}
	cleanup := func() {}
	if m.PrepareHTTP != nil {
		var err error
		cleanup, err = m.PrepareHTTP(ctx)
		if err != nil {
			return nil, err
		}
	}
	defer cleanup()
	type result struct {
		cert *tls.Certificate
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cert, err := issuer.GetCertificate(&tls.ClientHelloInfo{ServerName: domain, SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256}, SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
		done <- result{cert, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			// A failed registration retains its original contact in autocert.
			// Allow a corrected email/configuration to take effect on retry.
			m.mu.Lock()
			delete(m.issuers, domain)
			delete(m.handlers, domain)
			m.mu.Unlock()
			return nil, fmt.Errorf("выпуск/продление сертификата %s: %w", domain, res.err)
		}
		if res.cert == nil || len(res.cert.Certificate) == 0 {
			return nil, fmt.Errorf("ACME вернул пустой сертификат")
		}
		var chain []byte
		for _, der := range res.cert.Certificate {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		key, err := x509.MarshalPKCS8PrivateKey(res.cert.PrivateKey)
		if err != nil {
			return nil, err
		}
		return ParsePair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), domain)
	}
}

func (m *Manager) record(name string, pair *Pair, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.status[name]
	state.Domain = name
	if err != nil {
		state.Error = err.Error()
	} else {
		state.Error = ""
		state.Fingerprint = tlsutil.Fingerprint(pair.Leaf)
		state.Expires = pair.Leaf.NotAfter
	}
	m.status[name] = state
}

func (m *Manager) panel(ctx context.Context, cfg *config.Config) (*Pair, error) {
	spec := cfg.System.Panel.TLS
	switch spec.Mode {
	case "acme":
		return m.acme(ctx, spec.Domain, spec.Email)
	case "custom":
		return ReadPair(spec.CertFile, spec.KeyFile, "")
	default:
		cert, key, _, err := tlsutil.EnsureSelfSigned(m.Dir, cfg.System.Hostname)
		if err != nil {
			return nil, err
		}
		return ReadPair(cert, key, "")
	}
}

func (m *Manager) Panel(ctx context.Context, cfg *config.Config) (string, error) {
	m.op.Lock()
	defer m.op.Unlock()
	pair, err := m.panel(ctx, cfg)
	m.record("panel", pair, err)
	if err != nil {
		return "", err
	}
	file := filepath.Join(m.Dir, "panel-managed.pem")
	_, err = writePair(file, pair)
	return file, err
}

func (m *Manager) VPN(ctx context.Context, cfg *config.Config, server config.VPNServer, dir string) (bool, error) {
	m.op.Lock()
	defer m.op.Unlock()
	oc, err := server.OcservConfig()
	if err != nil {
		return false, err
	}
	host, _, err := net.SplitHostPort(oc.PublicEndpoint)
	if err != nil {
		return false, fmt.Errorf("укажите публичный адрес OpenConnect в формате домен:порт")
	}
	var pair *Pair
	if oc.TLS == nil {
		return false, fmt.Errorf("не выбран сертификат OpenConnect")
	}
	switch oc.TLS.Mode {
	case "panel":
		pair, err = m.panel(ctx, cfg)
	case "acme":
		pair, err = m.acme(ctx, oc.TLS.Domain, oc.TLS.Email)
	case "custom":
		pair, err = ParsePair([]byte(oc.TLS.CertPEM), []byte(oc.TLS.PrivateKey), host)
	default:
		return false, fmt.Errorf("неизвестный управляемый режим TLS %q", oc.TLS.Mode)
	}
	if err == nil {
		pair, err = ParsePair(pair.Certificate, pair.Key, host)
	}
	m.record("vpn:"+server.ID, pair, err)
	if err != nil {
		return false, err
	}
	changed, err := writePair(filepath.Join(dir, "server.pem"), pair)
	if err != nil {
		return false, err
	}
	// Public export remains separate; the bundle never leaves the service.
	if err := system.WriteFileAtomic(filepath.Join(dir, "panel.crt"), pair.Certificate, 0o644); err != nil {
		return false, err
	}
	return changed, nil
}
