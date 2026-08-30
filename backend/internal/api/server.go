// Package api обслуживает веб-панель: HTTP API и отдачу самого интерфейса.
package api

import (
	"context"
	"crypto/tls"
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
	Store     *store.Store
	Engine    *apply.Engine
	Collector *runtime.Collector
	Logger    Logger
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

	httpServer *http.Server
}

type failCounter struct {
	count int
	until time.Time
	last  time.Time
}

const (
	loginFailureTTL = 30 * time.Minute
	maxLoginSources = 4096
)

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

func New(st *store.Store, engine *apply.Engine, collector *runtime.Collector, logger Logger) *Server {
	return &Server{
		Store:        st,
		Engine:       engine,
		Collector:    collector,
		Logger:       logger,
		csrfTokens:   map[string]string{},
		loginFails:   map[string]*failCounter{},
		draftVersion: 1,
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
		next.ServeHTTP(w, r)
	})
}

// Start поднимает HTTPS-панель.
func (s *Server) Start(ctx context.Context, cfg *config.Config, tlsDir string) error {
	certPath, keyPath, fingerprint, err := tlsutil.EnsureSelfSigned(tlsDir, cfg.System.Hostname)
	if err != nil {
		return fmt.Errorf("подготовка сертификата: %w", err)
	}
	if cfg.System.Panel.TLS.Mode == "custom" {
		certPath = cfg.System.Panel.TLS.CertFile
		keyPath = cfg.System.Panel.TLS.KeyFile
	}
	s.Logger.Infof("отпечаток сертификата панели: %s", fingerprint)

	addr := fmt.Sprintf(":%d", cfg.System.Panel.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(logWriter{s.Logger}, "", 0),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("не удалось занять порт %d: %w", cfg.System.Panel.Port, err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	go s.pruneLoop(ctx)

	s.Logger.Infof("панель доступна на порту %d", cfg.System.Panel.Port)
	err = s.httpServer.ServeTLS(ln, certPath, keyPath)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
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
			s.pruneLoginFailures(time.Now())
			if err := s.Store.PruneSessions(); err != nil {
				s.Logger.Warnf("уборка сессий: %v", err)
			}
			if err := s.Store.PruneRevisions(50); err != nil {
				s.Logger.Warnf("уборка ревизий: %v", err)
			}
		}
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
