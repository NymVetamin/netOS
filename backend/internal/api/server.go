// Package api обслуживает веб-панель: HTTP API и отдачу самого интерфейса.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/ddns"
	"github.com/netos-router/netos/internal/tlsutil"
)

// webFS содержит собранный интерфейс. Каталог webdist наполняется сборкой
// фронтенда; заглушки достаточно, чтобы бинарник собирался и без неё.
//
//go:embed all:webdist
var webFS embed.FS

// ComponentProbe отвечает на вопрос, что из каталога стоит на машине и что из
// установленного работает прямо сейчас. Панель показывает оба состояния: между
// «пакет установлен» и «демон обслуживает сеть» есть разница, и по одному
// только первому непонятно, кто из двух установленных серверов DHCP работает.
type ComponentProbe interface {
	Status(ctx context.Context) map[string]bool
	Running(ctx context.Context) map[string]bool
}

// Server — веб-панель.
type Server struct {
	Store       *store.Store
	Engine      *apply.Engine
	Collector   *runtime.Collector
	Traffic     *runtime.TrafficHistory
	Maintenance *Maintenance
	Logger      Logger
	// Components может быть nil: панель обязана работать и без опроса машины,
	// тогда каталог отдаётся без состояний.
	Components ComponentProbe
	DDNS       *ddns.Controller

	// draft — конфигурация, которую администратор редактирует, но ещё не
	// применил.
	draftMu sync.RWMutex
	draft   *config.Config
	// draftVersion реализует optimistic locking для вкладок и нескольких
	// администраторов. Любая смена черновика увеличивает номер.
	draftVersion  uint64
	draftApplying bool

	// csrfTokens связывает сессию с её токеном защиты от подделки запросов.
	csrfMu     sync.RWMutex
	csrfTokens map[string]string

	// loginFails считает неудачные попытки входа по адресу источника.
	loginMu    sync.Mutex
	loginFails map[string]*failCounter
	loginSlots chan struct{}

	httpServer        *http.Server
	challengeServer   *http.Server
	Listen            func(network, address string) (net.Listener, error)
	ACMEFactory       acmeManagerFactory
	ACMEHTTPAddress   string
	ACMECheckInterval time.Duration
	Ready             func() error
}

type failCounter struct {
	count int
	until time.Time
	last  time.Time
}

const (
	loginFailureTTL     = 30 * time.Minute
	maxLoginSources     = 4096
	maxConcurrentLogins = 2
)

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

func New(st *store.Store, engine *apply.Engine, collector *runtime.Collector, logger Logger) *Server {
	return &Server{
		Store:             st,
		Engine:            engine,
		Collector:         collector,
		Logger:            logger,
		Listen:            net.Listen,
		ACMEFactory:       newProductionACMEManager,
		ACMEHTTPAddress:   ":80",
		ACMECheckInterval: 6 * time.Hour,
		csrfTokens:        map[string]string{},
		loginFails:        map[string]*failCounter{},
		loginSlots:        make(chan struct{}, maxConcurrentLogins),
		draftVersion:      1,
	}
}

// Routes собирает маршрутизацию.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// --- без аутентификации ---
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/ping", s.handlePing)

	// --- требуют входа ---
	auth := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireAuth(h))
	}

	auth("POST /api/logout", s.handleLogout)
	auth("GET /api/session", s.handleSession)
	auth("POST /api/password", s.handleChangePassword)
	auth("POST /api/wireguard/keypair", s.handleWireGuardKeypair)
	auth("POST /api/xray/keypair", s.handleXrayKeypair)
	auth("GET /api/vpn-servers/{id}/certificate", s.handleVPNServerCertificate)

	auth("GET /api/config", s.handleGetConfig)
	auth("PUT /api/config", s.handleSaveConfig)
	auth("POST /api/config/validate", s.handleValidate)
	auth("POST /api/config/plan", s.handlePlan)
	auth("POST /api/config/apply", s.handleApply)
	auth("POST /api/config/confirm", s.handleConfirm)
	auth("POST /api/config/rollback", s.handleRollback)
	auth("POST /api/config/discard", s.handleDiscard)

	auth("GET /api/revisions", s.handleRevisions)
	auth("GET /api/revisions/{id}", s.handleRevision)
	auth("POST /api/revisions/{id}/restore", s.handleRestoreRevision)

	auth("GET /api/catalog", s.handleCatalog)
	auth("GET /api/status", s.handleStatus)
	auth("GET /api/ddns/status", s.handleDDNSStatus)
	auth("GET /api/statistics", s.handleStatistics)
	auth("GET /api/maintenance/status", s.handleMaintenanceStatus)
	auth("GET /api/backups", s.handleBackups)
	auth("GET /api/backups/{name}", s.handleBackupDownload)
	auth("POST /api/backups", s.handleCreateBackup)
	auth("DELETE /api/backups/{name}", s.handleDeleteBackup)
	auth("POST /api/maintenance/restore", s.handleMaintenanceRestore)
	auth("POST /api/maintenance/update", s.handleMaintenanceUpdate)
	auth("POST /api/maintenance/panel", s.handleMaintenancePanel)
	auth("GET /api/clients", s.handleClients)
	auth("GET /api/interfaces", s.handleInterfaces)
	auth("GET /api/leases", s.handleLeases)
	auth("GET /api/arp", s.handleARP)
	auth("GET /api/routes", s.handleRoutes)
	auth("GET /api/audit", s.handleAudit)
	auth("GET /api/render", s.handleRenderList)
	auth("GET /api/render/{kind}", s.handleRender)

	// --- сам интерфейс ---
	mux.Handle("/", s.spaHandler())

	return s.withCommonHeaders(mux)
}

// spaHandler отдаёт собранный интерфейс, а неизвестные пути возвращает на
// index.html — маршрутизация внутри одностраничного приложения своя.
func (s *Server) spaHandler() http.Handler {
	sub, err := fs.Sub(webFS, "webdist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "интерфейс не собран", http.StatusServiceUnavailable)
		})
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Панель управляет роутером: встраивание в чужую страницу и утечка
		// адреса через Referer здесь совершенно ни к чему.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// Start поднимает HTTPS-панель.
func (s *Server) Start(ctx context.Context, cfg *config.Config, tlsDir string) error {
	var certPath, keyPath, fingerprint string
	var acmeManager acmeCertificateManager
	var challengeErr <-chan error
	var err error
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	switch cfg.System.Panel.TLS.Mode {
	case "custom":
		certPath = cfg.System.Panel.TLS.CertFile
		keyPath = cfg.System.Panel.TLS.KeyFile
		fingerprint, err = customTLSFingerprint(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("проверка пользовательского сертификата: %w", err)
		}
	case "acme":
		factory := s.ACMEFactory
		if factory == nil {
			factory = newProductionACMEManager
		}
		manager, factoryErr := factory(acmeCacheDir(tlsDir, cfg.System.Panel.TLS.Email), cfg.System.Panel.TLS.Domain, cfg.System.Panel.TLS.Email)
		if factoryErr != nil {
			return fmt.Errorf("подготовка ACME: %w", factoryErr)
		}
		acmeManager = manager
		listen := s.Listen
		if listen == nil {
			listen = net.Listen
		}
		challengeAddress := s.ACMEHTTPAddress
		if challengeAddress == "" {
			challengeAddress = ":80"
		}
		challengeListener, listenErr := listen("tcp", challengeAddress)
		if listenErr != nil {
			return fmt.Errorf("не удалось занять HTTP-порт проверки ACME %s: %w", challengeAddress, listenErr)
		}
		s.challengeServer = &http.Server{
			Addr: challengeAddress, Handler: manager.HTTPHandler(http.HandlerFunc(acmeFallback)),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
			ErrorLog: log.New(logWriter{s.Logger}, "", 0),
		}
		challengeDone := make(chan error, 1)
		go func() {
			serveErr := s.challengeServer.Serve(challengeListener)
			if serveErr == http.ErrServerClosed {
				serveErr = nil
			}
			challengeDone <- serveErr
		}()
		challengeErr = challengeDone
		cert, issueErr := prefetchACMECertificateContext(ctx, manager, cfg.System.Panel.TLS.Domain)
		if issueErr != nil {
			_ = s.challengeServer.Close()
			<-challengeDone
			return issueErr
		}
		parsed, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			_ = s.challengeServer.Close()
			<-challengeDone
			return fmt.Errorf("разбор сертификата ACME: %w", parseErr)
		}
		fingerprint = tlsutil.Fingerprint(parsed)
		tlsConfig = manager.TLSConfig().Clone()
		tlsConfig.MinVersion = tls.VersionTLS12
	case "selfsigned", "":
		certPath, keyPath, fingerprint, err = tlsutil.EnsureSelfSigned(tlsDir, cfg.System.Hostname)
		if err != nil {
			return fmt.Errorf("подготовка сертификата: %w", err)
		}
	default:
		return fmt.Errorf("неизвестный режим TLS %q", cfg.System.Panel.TLS.Mode)
	}
	s.Logger.Infof("отпечаток сертификата панели: %s", fingerprint)

	addr := fmt.Sprintf(":%d", cfg.System.Panel.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      15 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          log.New(logWriter{s.Logger}, "", 0),
		TLSConfig:         tlsConfig,
	}

	listen := s.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", addr)
	if err != nil {
		if s.challengeServer != nil {
			_ = s.challengeServer.Close()
			<-challengeErr
		}
		return fmt.Errorf("не удалось занять порт %d: %w", cfg.System.Panel.Port, err)
	}

	// The shutdown context must remain usable after the parent has been
	// cancelled; deriving it from ctx would cancel Shutdown immediately.
	// #nosec G118 -- this goroutine is bounded by ctx and a five-second timeout.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		if s.challengeServer != nil {
			_ = s.challengeServer.Shutdown(shutdownCtx)
		}
	}()

	go s.pruneLoop(ctx)
	if acmeManager != nil {
		go s.monitorACMECertificate(ctx, acmeManager, cfg.System.Panel.TLS.Domain, fingerprint)
	}

	serveDone := make(chan error, 1)
	go func() {
		serveErr := s.httpServer.ServeTLS(ln, certPath, keyPath)
		if serveErr == http.ErrServerClosed {
			serveErr = nil
		}
		serveDone <- serveErr
	}()
	serverName := cfg.System.Hostname
	if cfg.System.Panel.TLS.Mode == "acme" {
		serverName = strings.TrimSuffix(strings.ToLower(cfg.System.Panel.TLS.Domain), ".")
	}
	if err := waitPanelTLSReady(ctx, cfg.System.Panel.Port, serverName, serveDone); err != nil {
		_ = s.httpServer.Close()
		if s.challengeServer != nil {
			_ = s.challengeServer.Close()
		}
		return err
	}
	if s.Ready != nil {
		if err := s.Ready(); err != nil {
			_ = s.httpServer.Close()
			if s.challengeServer != nil {
				_ = s.challengeServer.Close()
			}
			return fmt.Errorf("маркер готовности панели: %w", err)
		}
	}
	s.Logger.Infof("панель доступна на порту %d", cfg.System.Panel.Port)
	if challengeErr == nil {
		return <-serveDone
	}
	select {
	case err := <-serveDone:
		return err
	case err := <-challengeErr:
		if err == nil && ctx.Err() != nil {
			return <-serveDone
		}
		_ = s.httpServer.Close()
		return fmt.Errorf("HTTP endpoint ACME остановлен: %w", err)
	}
}

func (s *Server) monitorACMECertificate(ctx context.Context, manager acmeCertificateManager, domain, fingerprint string) {
	interval := s.ACMECheckInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cert, err := prefetchACMECertificateContext(ctx, manager, domain)
			if err != nil {
				s.Logger.Errorf("проверка сертификата ACME: %v", err)
				continue
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				s.Logger.Errorf("проверка сертификата ACME: разбор X.509: %v", err)
				continue
			}
			current := tlsutil.Fingerprint(leaf)
			if current != fingerprint {
				s.Logger.Infof("сертификат ACME обновлён; новый отпечаток: %s; действует до %s", current, leaf.NotAfter.UTC().Format(time.RFC3339))
				fingerprint = current
			}
			if remaining := time.Until(leaf.NotAfter); remaining < 14*24*time.Hour {
				s.Logger.Warnf("сертификат ACME для %s истекает через %s", domain, remaining.Round(time.Hour))
			}
		}
	}
}

func waitPanelTLSReady(ctx context.Context, port int, serverName string, serveDone <-chan error) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: true, // #nosec G402 -- loopback readiness probe
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 750 * time.Millisecond}
	url := "https://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port)) + "/api/ping"
	for {
		response, err := client.Get(url)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("local /api/ping returned HTTP %d", response.StatusCode)
		}
		select {
		case serveErr := <-serveDone:
			return fmt.Errorf("панель остановилась до TLS-готовности: %w", serveErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("панель не прошла локальный TLS handshake за 10s: %w", err)
		case <-ticker.C:
		}
	}
}

func customTLSFingerprint(certPath, keyPath string) (string, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return "", err
	}
	if len(pair.Certificate) == 0 {
		return "", fmt.Errorf("файл сертификата не содержит X.509 сертификат")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", err
	}
	return tlsutil.Fingerprint(cert), nil
}

// pruneLoop убирает просроченные сессии и лишние ревизии.
func (s *Server) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pruneOnce()
		}
	}
}

func (s *Server) pruneOnce() {
	s.pruneLoginFailures(time.Now())
	expired, err := s.Store.PruneSessions()
	if err != nil {
		s.Logger.Warnf("уборка сессий: %v", err)
	} else if len(expired) > 0 {
		s.csrfMu.Lock()
		for _, token := range expired {
			delete(s.csrfTokens, token)
		}
		s.csrfMu.Unlock()
	}
	if err := s.Store.PruneRevisions(50); err != nil {
		s.Logger.Warnf("уборка ревизий: %v", err)
	}
	if err := s.Store.PruneAudit(10_000); err != nil {
		s.Logger.Warnf("уборка журнала аудита: %v", err)
	}
}

// ---------------------------------------------------------------------------
// вспомогательное
// ---------------------------------------------------------------------------

type logWriter struct{ l Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.l.Warnf("%s", strings.TrimSpace(string(p)))
	return len(p), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

type errorResponse struct {
	Error string `json:"error"`
	// Problems заполняется, когда запрос отклонён валидатором: интерфейс
	// подсвечивает конкретные поля формы.
	Problems []config.Problem `json:"problems,omitempty"`
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, errorResponse{Error: fmt.Sprintf(format, args...)})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("в теле запроса больше одного JSON-значения")
		}
		return err
	}
	return nil
}

// clientIP определяет адрес источника. Заголовкам вроде X-Forwarded-For
// намеренно не доверяем: панель слушает напрямую, и подделанный заголовок
// сбил бы и журнал аудита, и счётчик неудачных входов.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
