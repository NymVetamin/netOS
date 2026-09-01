package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/render"
	"github.com/netos-router/netos/internal/store"
)

var panelActivationStaleAfter = 2 * time.Minute

func generateWireGuardKeypair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func wireGuardPublicKey(privateKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("некорректный закрытый ключ WireGuard")
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (s *Server) handleWireGuardKeypair(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PrivateKey string `json:"private_key"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный запрос")
			return
		}
	}
	privateKey, publicKey, err := "", "", error(nil)
	responsePrivate := ""
	if input.PrivateKey == "" {
		privateKey, publicKey, err = generateWireGuardKeypair()
		responsePrivate = privateKey
	} else {
		privateKey = input.PrivateKey
		publicKey, err = wireGuardPublicKey(privateKey)
	}
	if err != nil {
		if input.PrivateKey != "" {
			writeError(w, http.StatusBadRequest, "некорректный закрытый ключ WireGuard")
		} else {
			writeError(w, http.StatusInternalServerError, "не удалось сгенерировать ключи WireGuard")
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"private_key": responsePrivate, "public_key": publicKey})
}

func xrayPublicKey(privateKey string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(privateKey, "="))
	if err != nil || len(decoded) != 32 {
		return "", errors.New("некорректный закрытый ключ Reality")
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (s *Server) handleXrayKeypair(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PrivateKey string `json:"private_key"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный запрос")
			return
		}
	}
	privateKey, publicKey := input.PrivateKey, ""
	var err error
	responsePrivate := ""
	if privateKey == "" {
		key, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
		if keyErr != nil {
			err = keyErr
		} else {
			privateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
			publicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			responsePrivate = privateKey
		}
	} else {
		publicKey, err = xrayPublicKey(privateKey)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "не удалось обработать ключи Reality")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"private_key": responsePrivate, "public_key": publicKey})
}

func (s *Server) handleVPNServerCertificate(w http.ResponseWriter, r *http.Request) {
	if s.Engine == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}
	cfg := s.Engine.Current()
	if cfg == nil {
		writeError(w, http.StatusNotFound, "конфигурация недоступна")
		return
	}
	for _, server := range cfg.VPNServers {
		if server.ID != r.PathValue("id") || (server.Type != "ocserv" && server.Type != "ikev2") || !server.Enabled {
			continue
		}
		path := filepath.Join(vpnGeneratedDir, fmt.Sprintf("ocserv-srv%d-tls", server.Index), "panel.crt")
		filename := fmt.Sprintf("netos-openconnect-%d.crt", server.Index)
		if server.Type == "ikev2" {
			path = filepath.Join(vpnGeneratedDir, "strongswan", "x509", "server.crt")
			filename = fmt.Sprintf("netos-ikev2-%d-ca.crt", server.Index)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			writeError(w, http.StatusNotFound, "сертификат ещё не выпущен")
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}
	writeError(w, http.StatusNotFound, "VPN-сервер не найден")
}

type ctxKey string

const (
	ctxUser ctxKey = "user"
	ctxRole ctxKey = "role"
)

// initialCredentialsPath — файл с данными первого запуска, который пишет
// netosd, а читает установщик. Панель его удаляет: пароль, который уже
// увидели, не должен оставаться на диске открытым текстом.
//
// Переменная, а не константа: проверять уборку надо на временном файле, а не
// на настоящем /var/lib/netos машины, где идёт сборка.
var initialCredentialsPath = "/var/lib/netos/initial-credentials"
var vpnGeneratedDir = "/var/lib/netos/generated"
var panelPortAvailable = func(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	return listener.Close()
}

// requireAuth проверяет сессию и, для изменяющих запросов, CSRF-токен.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется вход")
			return
		}
		username, err := s.Store.SessionUser(cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "сессия истекла")
			return
		}
		user, err := s.Store.UserByName(username)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "пользователь не найден")
			return
		}
		if user.Role != "admin" && (user.Role != "viewer" || !viewerAllowed(r)) {
			writeError(w, http.StatusForbidden, "недостаточно прав")
			return
		}

		// Cookie отправляется браузером автоматически, поэтому одной её мало:
		// для любого изменяющего запроса требуем заголовок, который чужая
		// страница выставить не сможет.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.csrfMu.RLock()
			want := s.csrfTokens[cookie.Value]
			s.csrfMu.RUnlock()
			if want == "" || r.Header.Get(csrfHeader) != want {
				writeError(w, http.StatusForbidden, "неверный CSRF-токен")
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxUser, username)
		ctx = context.WithValue(ctx, ctxRole, user.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func viewerAllowed(r *http.Request) bool {
	if r.URL.Path == "/api/logout" || r.URL.Path == "/api/password" {
		return true
	}
	if r.Method != http.MethodGet {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/vpn-servers/") && strings.HasSuffix(r.URL.Path, "/certificate") {
		return true
	}
	switch r.URL.Path {
	case "/api/session", "/api/config", "/api/catalog", "/api/status", "/api/ddns/status", "/api/statistics", "/api/maintenance/status", "/api/clients",
		"/api/interfaces", "/api/leases", "/api/arp", "/api/routes", "/api/audit",
		"/api/revisions":
		return true
	default:
		return false
	}
}

func userOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUser).(string); ok {
		return v
	}
	return ""
}

func roleOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRole).(string); ok {
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// Сессии
// ---------------------------------------------------------------------------

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"service": "netos", "ok": true})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, blocked := s.loginBlocked(ip); blocked {
		writeError(w, http.StatusTooManyRequests,
			"слишком много неудачных попыток, повторите через %d секунд", int(wait.Seconds()))
		return
	}
	if s.loginSlots == nil {
		s.loginSlots = make(chan struct{}, maxConcurrentLogins)
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		writeError(w, http.StatusTooManyRequests, "сервер занят проверкой учётных данных, повторите попытку")
		return
	}

	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный запрос")
		return
	}
	if len(req.Username) == 0 || len(req.Username) > 64 || len(req.Password) == 0 || len(req.Password) > maxPasswordBytes {
		s.recordLoginFailure(ip)
		writeError(w, http.StatusUnauthorized, "неверное имя пользователя или пароль")
		return
	}

	user, err := s.Store.UserByName(req.Username)
	// Проверку хэша выполняем даже для несуществующего пользователя, иначе по
	// времени ответа можно выяснить, какие имена существуют.
	valid := false
	if err == nil {
		valid = VerifyPassword(req.Password, user.PasswordHash)
	} else {
		_ = VerifyPassword(req.Password, "$argon2id$v=19$m=65536,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	}

	if !valid {
		s.recordLoginFailure(ip)
		_ = s.Store.Audit(store.AuditEntry{
			User: req.Username, Action: "login", SourceIP: ip, Success: false,
			Detail: "неверные учётные данные",
		})
		writeError(w, http.StatusUnauthorized, "неверное имя пользователя или пароль")
		return
	}

	s.clearLoginFailures(ip)

	token, err := GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать сессию")
		return
	}
	csrf, err := GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать сессию")
		return
	}
	evicted, err := s.Store.CreateSession(token, user.Username, ip, sessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить сессию")
		return
	}

	s.csrfMu.Lock()
	for _, staleToken := range evicted {
		delete(s.csrfTokens, staleToken)
	}
	s.csrfTokens[token] = csrf
	s.csrfMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	_ = s.Store.TouchLogin(user.Username)
	// Пароль первого запуска уже дошёл до того, кто им воспользовался, —
	// держать его на диске открытым текстом больше незачем. Обязательной
	// смены пароля нет, поэтому уборка привязана ко входу, а не к ней.
	_ = os.Remove(initialCredentialsPath)
	_ = s.Store.Audit(store.AuditEntry{User: user.Username, Action: "login", SourceIP: ip, Success: true})

	writeJSON(w, http.StatusOK, loginResponse{
		Username:  user.Username,
		Role:      user.Role,
		CSRFToken: csrf,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.Store.DeleteSession(cookie.Value)
		s.csrfMu.Lock()
		delete(s.csrfTokens, cookie.Value)
		s.csrfMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	user, err := s.Store.UserByName(userOf(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "сессия не найдена")
		return
	}
	s.csrfMu.Lock()
	csrf := s.csrfTokens[cookie.Value]
	if csrf == "" {
		csrf, err = GenerateToken()
		if err == nil {
			s.csrfTokens[cookie.Value] = csrf
		}
	}
	s.csrfMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обновить защиту сессии")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   user.Username,
		"role":       user.Role,
		"csrf_token": csrf,
		"last_login": user.LastLogin,
	})
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный запрос")
		return
	}
	if len(req.New) < 10 || len(req.New) > maxPasswordBytes {
		writeError(w, http.StatusBadRequest, "пароль должен быть не короче 10 символов")
		return
	}

	username := userOf(r)
	user, err := s.Store.UserByName(username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "пользователь не найден")
		return
	}
	if !VerifyPassword(req.Current, user.PasswordHash) {
		writeError(w, http.StatusForbidden, "текущий пароль указан неверно")
		return
	}

	hash, err := HashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обработать пароль")
		return
	}
	revoked, err := s.Store.UpdatePasswordAndDeleteSessions(username, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить пароль")
		return
	}
	s.csrfMu.Lock()
	for _, token := range revoked {
		delete(s.csrfTokens, token)
	}
	s.csrfMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	// Пароль сменён — файл с данными первого запуска больше не нужен и не
	// должен лежать на диске.
	_ = os.Remove(initialCredentialsPath)

	_ = s.Store.Audit(store.AuditEntry{
		User: username, Action: "password_change", SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// Ограничение попыток входа
// ---------------------------------------------------------------------------

func (s *Server) loginBlocked(ip string) (time.Duration, bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	f, ok := s.loginFails[ip]
	now := time.Now()
	if !ok {
		return 0, false
	}
	if now.Sub(f.last) > loginFailureTTL {
		delete(s.loginFails, ip)
		return 0, false
	}
	if now.After(f.until) {
		return 0, false
	}
	return time.Until(f.until), true
}

// recordLoginFailure наращивает паузу после каждой неудачи: пять попыток
// проходят свободно, дальше задержка растёт до минуты.
func (s *Server) recordLoginFailure(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	f, ok := s.loginFails[ip]
	if !ok || now.Sub(f.last) > loginFailureTTL {
		if !ok && len(s.loginFails) >= maxLoginSources {
			s.evictOldestLoginFailure()
		}
		f = &failCounter{}
		s.loginFails[ip] = f
	}
	f.last = now
	f.count++
	if f.count > 5 {
		delay := time.Duration(f.count-5) * 10 * time.Second
		if delay > time.Minute {
			delay = time.Minute
		}
		f.until = now.Add(delay)
	}
}

func (s *Server) evictOldestLoginFailure() {
	var oldestIP string
	var oldest time.Time
	for ip, counter := range s.loginFails {
		if oldestIP == "" || counter.last.Before(oldest) {
			oldestIP = ip
			oldest = counter.last
		}
	}
	if oldestIP != "" {
		delete(s.loginFails, oldestIP)
	}
}

func (s *Server) pruneLoginFailures(now time.Time) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	for ip, counter := range s.loginFails {
		if now.Sub(counter.last) > loginFailureTTL {
			delete(s.loginFails, ip)
		}
	}
}

func (s *Server) clearLoginFailures(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginFails, ip)
}

// ---------------------------------------------------------------------------
// Конфигурация
// ---------------------------------------------------------------------------

// currentDraft возвращает редактируемую конфигурацию: черновик, если он есть,
// иначе копию применённой.
func (s *Server) draftSnapshot() (*config.Config, bool, uint64) {
	s.draftMu.RLock()
	defer s.draftMu.RUnlock()
	if s.draft != nil {
		return s.draft, true, s.draftVersion
	}
	return s.Engine.Current(), false, s.draftVersion
}

func (s *Server) currentDraft() *config.Config {
	cfg, _, _ := s.draftSnapshot()
	return cfg
}

type configResponse struct {
	Config   *config.Config   `json:"config"`
	Dirty    bool             `json:"dirty"`
	Problems []config.Problem `json:"problems"`
	Pending  bool             `json:"pending_confirmation"`
	Deadline *time.Time       `json:"confirm_deadline,omitempty"`
	// Rollback заполняется, если последнее применение было откачено. Панель
	// обязана показать это явно: иначе администратор увидит вернувшиеся
	// старые настройки и не поймёт, почему его изменения исчезли.
	Rollback     *apply.RollbackInfo `json:"rollback,omitempty"`
	DraftVersion uint64              `json:"draft_version"`
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, dirty, version := s.draftSnapshot()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация ещё не загружена")
		return
	}

	pending, deadline := s.Engine.Pending()
	visibleCfg := cfg
	if roleOf(r) != "admin" {
		redacted, err := redactConfig(cfg)
		if err != nil {
			// Молча отдать null нельзя: панель показала бы пустую
			// конфигурацию вместо скрытых секретов и ввела бы в заблуждение.
			writeError(w, http.StatusInternalServerError, "не удалось скрыть секреты: %v", err)
			return
		}
		visibleCfg = redacted
	}
	resp := configResponse{
		Config:       visibleCfg,
		Dirty:        dirty,
		Problems:     cfg.Validate().Problems,
		Pending:      pending,
		Rollback:     s.Engine.LastRollback(),
		DraftVersion: version,
	}
	if pending {
		resp.Deadline = &deadline
	}
	writeJSON(w, http.StatusOK, resp)
}

func redactConfig(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	for i := range out.WANs {
		out.WANs[i].Password = ""
	}
	for i := range out.WiFi {
		for j := range out.WiFi[i].SSIDs {
			out.WiFi[i].SSIDs[j].Password = ""
		}
	}
	for i := range out.Channels {
		redactSecretValues(out.Channels[i].Config)
	}
	for i := range out.VPNServers {
		redactSecretValues(out.VPNServers[i].Config)
		for j := range out.VPNServers[i].Peers {
			for key := range out.VPNServers[i].Peers[j].Credentials {
				out.VPNServers[i].Peers[j].Credentials[key] = ""
			}
		}
	}
	out.DDNS.Token = ""
	out.DDNS.Password = ""
	return &out, nil
}

func redactSecretValues(values map[string]any) {
	for key, value := range values {
		normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(key))
		if strings.Contains(normalized, "password") || strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "private_key") || strings.Contains(normalized, "preshared_key") ||
			strings.Contains(normalized, "token") {
			values[key] = ""
			continue
		}
		switch nested := value.(type) {
		case map[string]any:
			redactSecretValues(nested)
		case []any:
			for _, item := range nested {
				if object, ok := item.(map[string]any); ok {
					redactSecretValues(object)
				}
			}
		}
	}
}

func (s *Server) handleDDNSStatus(w http.ResponseWriter, _ *http.Request) {
	if s.DDNS == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.DDNS.Status())
}

func (s *Server) handleStatistics(w http.ResponseWriter, r *http.Request) {
	if s.Traffic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"points": []any{}})
		return
	}
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		var err error
		hours, err = strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "диапазон должен быть целым числом часов")
			return
		}
	}
	if hours < 1 || hours > 168 {
		writeError(w, http.StatusBadRequest, "диапазон должен быть от 1 до 168 часов")
		return
	}
	var names []string
	for _, name := range strings.Split(r.URL.Query().Get("interfaces"), ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !config.ValidInterfaceName(name) {
			writeError(w, http.StatusBadRequest, "некорректное имя интерфейса %q", name)
			return
		}
		names = append(names, name)
	}
	points := s.Traffic.Points(time.Now().UTC().Add(-time.Duration(hours)*time.Hour), names)
	writeJSON(w, http.StatusOK, map[string]any{"points": points, "interval_seconds": int(s.Traffic.Interval.Seconds())})
}

func (s *Server) handleMaintenanceStatus(w http.ResponseWriter, r *http.Request) {
	if s.Maintenance == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, s.Maintenance.Status(r.Context()))
}

func (s *Server) handleBackups(w http.ResponseWriter, _ *http.Request) {
	if s.Maintenance == nil {
		writeError(w, http.StatusServiceUnavailable, "обслуживание недоступно")
		return
	}
	backups, err := s.Maintenance.Backups()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups})
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if s.Maintenance == nil {
		writeError(w, http.StatusServiceUnavailable, "обслуживание недоступно")
		return
	}
	name := r.PathValue("name")
	file, err := s.Maintenance.OpenBackup(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "резервная копия не найдена")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	s.scheduleMaintenance(w, r, "backup", "", "backup")
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	if s.Maintenance == nil {
		writeError(w, http.StatusServiceUnavailable, "обслуживание недоступно")
		return
	}
	name := r.PathValue("name")
	if err := s.Maintenance.DeleteBackup(name); err != nil {
		writeError(w, http.StatusNotFound, "резервная копия не найдена")
		return
	}
	_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: "backup-delete", Target: name, Success: true})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMaintenanceRestore(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	if err := readJSON(r, &input); err != nil || input.Confirm != "RESTORE" {
		writeError(w, http.StatusBadRequest, "для восстановления требуется подтверждение RESTORE")
		return
	}
	s.scheduleMaintenance(w, r, "restore", input.Name, "restore")
}

func (s *Server) handleMaintenanceUpdate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version string `json:"version"`
		Confirm string `json:"confirm"`
	}
	if err := readJSON(r, &input); err != nil || input.Confirm != "UPDATE" {
		writeError(w, http.StatusBadRequest, "для обновления требуется подтверждение UPDATE")
		return
	}
	s.scheduleMaintenance(w, r, "update", input.Version, "update")
}

func (s *Server) handleMaintenancePanel(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Panel   config.Panel `json:"panel"`
		Confirm string       `json:"confirm"`
	}
	if err := readJSON(r, &input); err != nil || input.Confirm != "RESTART" {
		writeError(w, http.StatusBadRequest, "для смены адреса панели требуется подтверждение RESTART")
		return
	}
	if s.Maintenance == nil || s.Store == nil || s.Engine == nil {
		writeError(w, http.StatusServiceUnavailable, "обслуживание панели недоступно")
		return
	}
	if pending, _ := s.Engine.Pending(); pending {
		writeError(w, http.StatusConflict, "сначала подтвердите или откатите предыдущее применение")
		return
	}

	s.draftMu.Lock()
	if s.draft != nil || s.draftApplying {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "сначала примените или отмените текущий черновик")
		return
	}
	s.draftApplying = true
	s.draftMu.Unlock()
	releaseLock := true
	defer func() {
		if releaseLock {
			s.draftMu.Lock()
			s.draftApplying = false
			s.draftMu.Unlock()
		}
	}()

	current := s.Engine.Current()
	if current == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось скопировать конфигурацию панели: %v", err)
		return
	}
	var next config.Config
	if err := json.Unmarshal(encoded, &next); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось скопировать конфигурацию панели: %v", err)
		return
	}
	next.System.Panel = input.Panel
	for i := range next.Firewall.Rules {
		if next.Firewall.Rules[i].ID == config.RulePanel {
			next.Firewall.Rules[i].DstPort = strconv.Itoa(input.Panel.Port)
		}
	}
	if result := next.Validate(); result.HasErrors() {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{
			Error: "параметры панели содержат ошибки", Problems: result.Problems,
		})
		return
	}
	if input.Panel.TLS.Mode == "custom" {
		if _, err := customTLSFingerprint(input.Panel.TLS.CertFile, input.Panel.TLS.KeyFile); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "сертификат и ключ не образуют рабочую TLS-пару: %v", err)
			return
		}
	}
	if input.Panel.TLS.Mode == "acme" && current.System.Panel.TLS.Mode != "acme" && current.System.Panel.Port != 80 {
		if err := panelPortAvailable(80); err != nil {
			writeError(w, http.StatusConflict, "порт 80 для проверки домена ACME уже занят: %v", err)
			return
		}
	}
	if input.Panel.Port != current.System.Panel.Port {
		if err := panelPortAvailable(input.Panel.Port); err != nil {
			writeError(w, http.StatusConflict, "порт %d уже занят: %v", input.Panel.Port, err)
			return
		}
	}

	previous, err := s.Store.ActiveRevision()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось определить активную ревизию: %v", err)
		return
	}
	targetID, err := s.Store.CreateRevision(&next, userOf(r), "смена адреса/TLS веб-панели")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить ревизию панели: %v", err)
		return
	}
	if err := s.Store.SetRevisionState(targetID, store.StateApplying); err != nil {
		_ = s.Store.SetRevisionState(targetID, store.StateRolledBack)
		writeError(w, http.StatusInternalServerError, "не удалось подготовить ревизию панели: %v", err)
		return
	}
	if err := s.Maintenance.SchedulePanelActivation(r.Context(), targetID, previous.ID); err != nil {
		_ = s.Store.SetRevisionState(targetID, store.StateRolledBack)
		_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: "panel-restart", Target: strconv.FormatInt(targetID, 10), Detail: err.Error(), Success: false})
		writeError(w, http.StatusConflict, "%v", err)
		return
	}
	_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: "panel-restart", Target: strconv.FormatInt(targetID, 10), Detail: "перезапуск запланирован с автоматическим откатом", Success: true})
	releaseLock = false
	if panelActivationStaleAfter > 0 {
		go func() {
			// If systemd-run itself was accepted but never executed, the old daemon
			// remains alive. Do not leave configuration editing locked forever.
			time.Sleep(panelActivationStaleAfter)
			rev, err := s.Store.Revision(targetID)
			if err == nil && rev.State == store.StateApplying {
				_ = s.Store.SetRevisionState(targetID, store.StateRolledBack)
				s.draftMu.Lock()
				s.draftApplying = false
				s.draftMu.Unlock()
			}
		}()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"scheduled": true, "revision": targetID, "port": input.Panel.Port,
	})
}

func (s *Server) scheduleMaintenance(w http.ResponseWriter, r *http.Request, operation, argument, action string) {
	if s.Maintenance == nil {
		writeError(w, http.StatusServiceUnavailable, "обслуживание недоступно")
		return
	}
	if err := s.Maintenance.Schedule(r.Context(), operation, argument); err != nil {
		_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: action, Target: argument, Detail: err.Error(), Success: false})
		writeError(w, http.StatusConflict, "%v", err)
		return
	}
	_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: action, Target: argument, Detail: "операция запланирована", Success: true})
	writeJSON(w, http.StatusAccepted, map[string]any{"scheduled": true})
}

// handleSaveConfig сохраняет черновик. Применение — отдельным действием:
// администратор должен видеть план до того, как что-то изменится.
func (s *Server) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := readJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "некорректная конфигурация: %v", err)
		return
	}
	cfg.Normalize()

	result := cfg.Validate()
	if result.HasErrors() {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{
			Error:    "конфигурация содержит ошибки",
			Problems: result.Problems,
		})
		return
	}

	expected, ok := draftPrecondition(w, r)
	if !ok {
		return
	}
	if pending, _ := s.Engine.Pending(); pending {
		writeError(w, http.StatusConflict, "нельзя менять черновик до подтверждения или отката")
		return
	}
	s.draftMu.Lock()
	if s.draftApplying {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик сейчас применяется")
		return
	}
	if expected != s.draftVersion {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик уже изменён в другой вкладке; обновите страницу")
		return
	}
	// Черновик, совпавший с применённой конфигурацией, черновиком быть
	// перестаёт. Иначе администратор, изменивший значение и вернувший его
	// обратно, до конца сеанса видит полосу «есть несохранённые изменения» и
	// кнопку «Применить», которой нечего применять.
	dirty := !sameConfig(&cfg, s.Engine.Current())
	if dirty {
		s.draft = &cfg
	} else {
		s.draft = nil
	}
	s.draftVersion++
	version := s.draftVersion
	s.draftMu.Unlock()

	writeJSON(w, http.StatusOK, configResponse{
		Config:       &cfg,
		Dirty:        dirty,
		Problems:     result.Problems,
		DraftVersion: version,
	})
}

// sameConfig сравнивает конфигурации по содержимому. Сравниваем сериализацию,
// а не структуры: reflect.DeepEqual считает разными nil и пустой срез, а
// панель присылает то одно, то другое в зависимости от того, трогали ли раздел.
func sameConfig(a, b *config.Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

func (s *Server) handleDiscard(w http.ResponseWriter, r *http.Request) {
	expected, ok := draftPrecondition(w, r)
	if !ok {
		return
	}
	s.draftMu.Lock()
	if s.draftApplying {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик сейчас применяется")
		return
	}
	if expected != s.draftVersion {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик уже изменён в другой вкладке; обновите страницу")
		return
	}
	s.draft = nil
	s.draftVersion++
	version := s.draftVersion
	s.draftMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "draft_version": version})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := readJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "некорректная конфигурация")
		return
	}
	cfg.Normalize()
	writeJSON(w, http.StatusOK, cfg.Validate())
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentDraft()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}
	actions, err := s.Engine.Plan(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось построить план: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

type applyRequest struct {
	Comment      string `json:"comment"`
	DraftVersion uint64 `json:"draft_version"`
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный запрос: %v", err)
		return
	}
	s.draftMu.Lock()
	if req.DraftVersion != s.draftVersion {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик уже изменён в другой вкладке; обновите страницу")
		return
	}
	cfg := s.draft
	if cfg == nil {
		cfg = s.Engine.Current()
	}
	s.draftApplying = true
	s.draftMu.Unlock()
	defer func() {
		s.draftMu.Lock()
		s.draftApplying = false
		s.draftMu.Unlock()
	}()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}

	// Новое применение отменяет прошлое предупреждение об откате.
	s.Engine.ClearRollback()

	username := userOf(r)
	revID, err := s.Store.CreateRevision(cfg, username, req.Comment)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить ревизию: %v", err)
		return
	}
	if err := s.Store.SetRevisionState(revID, store.StateApplying); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось начать применение ревизии: %v", err)
		return
	}

	// Подтверждение требуется всегда, когда есть куда откатываться: именно оно
	// спасает администратора, закрывшего себе доступ правилом файрволла.
	// Изменение сети может оборвать именно тот HTTP-запрос, который его
	// запустил. Системная транзакция обязана дожить до постановки таймера
	// подтверждения или собственного отката независимо от соединения браузера.
	applyCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := s.Engine.Apply(applyCtx, cfg, revID, true)
	if err != nil {
		_ = s.Store.SetRevisionState(revID, store.StateRolledBack)
		_ = s.Store.Audit(store.AuditEntry{
			User: username, Action: "apply", Target: strconv.FormatInt(revID, 10),
			Detail: err.Error(), SourceIP: clientIP(r), Success: false,
		})
		// Черновик после неудачи остаётся прежним, вместе с тем значением, из-за
		// которого всё и упало. Это правильно — исправлять его администратору,
		// — но без подсказки следующая попытка бьётся в ту же стену.
		writeError(w, http.StatusInternalServerError,
			"применение не удалось: %v. Система откачена к прежней конфигурации; "+
				"исправьте черновик или отмените изменения", err)
		return
	}

	if !result.NeedsConfirm {
		if err := s.Store.MarkActive(revID); err != nil {
			s.Logger.Warnf("не удалось пометить ревизию активной: %v", err)
		}
		s.draftMu.Lock()
		s.draft = nil
		s.draftVersion++
		s.draftMu.Unlock()
	}

	_ = s.Store.Audit(store.AuditEntry{
		User: username, Action: "apply", Target: strconv.FormatInt(revID, 10),
		Detail: req.Comment, SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	revision, err := s.Engine.Confirm(s.Store.MarkActive)
	if err != nil {
		writeError(w, http.StatusConflict, "%v", err)
		return
	}

	s.draftMu.Lock()
	s.draft = nil
	s.draftVersion++
	s.draftMu.Unlock()

	_ = s.Store.Audit(store.AuditEntry{
		User: userOf(r), Action: "confirm", Target: strconv.FormatInt(revision, 10),
		SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	// Restoring the previous network can terminate the very HTTP connection
	// that requested the rollback. The system transaction must outlive it.
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Engine.Rollback(rollbackCtx); err != nil {
		writeError(w, http.StatusConflict, "%v", err)
		return
	}
	// New wires the engine callback to do this for both manual and timeout
	// rollbacks. Keep the handler idempotently safe for tests and embedders that
	// replace Engine after constructing Server.
	s.discardDraft()
	_ = s.Store.Audit(store.AuditEntry{
		User: userOf(r), Action: "rollback", SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// Ревизии
// ---------------------------------------------------------------------------

func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	revisions, err := s.Store.ListRevisions(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось получить историю: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
}

func (s *Server) handleRevision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "некорректный идентификатор")
		return
	}
	rev, err := s.Store.Revision(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "ревизия не найдена")
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

// handleRestoreRevision загружает старую ревизию в черновик. Применяет её
// администратор отдельно — так у него остаётся возможность посмотреть план.
func (s *Server) handleRestoreRevision(w http.ResponseWriter, r *http.Request) {
	expected, ok := draftPrecondition(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "некорректный идентификатор")
		return
	}
	rev, err := s.Store.Revision(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "ревизия не найдена")
		return
	}

	s.draftMu.Lock()
	if s.draftApplying || expected != s.draftVersion {
		s.draftMu.Unlock()
		writeError(w, http.StatusConflict, "черновик уже изменён или применяется; обновите страницу")
		return
	}
	s.draft = rev.Config
	s.draftVersion++
	version := s.draftVersion
	s.draftMu.Unlock()

	writeJSON(w, http.StatusOK, configResponse{
		Config:       rev.Config,
		Dirty:        true,
		Problems:     rev.Config.Validate().Problems,
		DraftVersion: version,
	})
}

func draftPrecondition(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	raw := strings.Trim(r.Header.Get("If-Match"), "\" ")
	if raw == "" {
		writeError(w, http.StatusPreconditionRequired, "для изменения черновика нужен If-Match")
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "некорректный If-Match")
		return 0, false
	}
	return v, true
}

// ---------------------------------------------------------------------------
// Наблюдение
// ---------------------------------------------------------------------------

// handleCatalog отдаёт список того, что netOS умеет устанавливать. Панель
// строит по нему раздел компонентов и подсказывает, чего не хватает для
// нужной функции.
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"components": config.Catalog}
	if s.Components != nil {
		// installed — полностью ли готов компонент (весь payload на диске,
		// закреплённая external-версия актуальна, штатные конфликтующие unit
		// погашены), running — чей демон
		// поднят. Желаемое состояние панель знает из конфигурации, а эти два
		// поля показывают живую машину: установленный компонент может быть
		// никем не выбран и не работать.
		resp["installed"] = s.Components.Status(r.Context())
		resp["running"] = s.Components.Running(r.Context())
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	cfg := s.Engine.Current()
	stats, err := s.Collector.InterfaceStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "чтение интерфейсов: %v", err)
		return
	}
	clients, err := s.Collector.Clients(r.Context(), localClientInterfaces(cfg))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "чтение клиентов: %v", err)
		return
	}

	online := 0
	for _, c := range clients {
		if c.Online {
			online++
		}
	}

	pending, deadline := s.Engine.Pending()
	resp := map[string]any{
		"hostname":        "",
		"uptime_seconds":  uptimeSeconds(),
		"interfaces":      stats,
		"clients_total":   len(clients),
		"clients_online":  online,
		"conntrack_count": s.Collector.ConntrackCount(),
		"pending_confirm": pending,
	}
	if cfg != nil {
		resp["hostname"] = cfg.System.Hostname
		resp["ipv6_mode"] = cfg.IPv6.Mode
		resp["dns_provider"] = cfg.DNS.Provider
		resp["dhcp_provider"] = cfg.DHCP.Provider
	}
	if pending {
		resp["confirm_deadline"] = deadline
	}
	if rb := s.Engine.LastRollback(); rb != nil {
		resp["rollback"] = rb
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	cfg := s.Engine.Current()
	clients, err := s.Collector.Clients(r.Context(), localClientInterfaces(cfg))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	// Дополняем наблюдаемые устройства тем, что администратор о них задал:
	// именем, каналом, блокировкой.
	if cfg != nil {
		known := map[string]config.Client{}
		for _, c := range cfg.Clients {
			known[c.MAC] = c
		}
		type enriched struct {
			MAC       string `json:"mac"`
			IP        string `json:"ip"`
			Hostname  string `json:"hostname"`
			Interface string `json:"interface"`
			Online    bool   `json:"online"`
			Source    string `json:"source"`
			Name      string `json:"name,omitempty"`
			Channel   string `json:"channel,omitempty"`
			Blocked   bool   `json:"blocked"`
		}
		out := make([]enriched, 0, len(clients))
		for _, c := range clients {
			e := enriched{
				MAC: c.MAC, IP: c.IP, Hostname: c.Hostname,
				Interface: c.Interface, Online: c.Online, Source: c.Source,
			}
			if k, ok := known[c.MAC]; ok {
				e.Name = k.Name
				e.Channel = k.Channel
				e.Blocked = k.Blocked
			}
			out = append(out, e)
		}
		writeJSON(w, http.StatusOK, map[string]any{"clients": out})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func localClientInterfaces(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil {
		return out
	}
	for _, network := range cfg.Networks {
		if !network.Enabled {
			continue
		}
		if name := cfg.InterfaceName(network.Interface); name != "" {
			out[name] = true
		}
	}
	return out
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	stats, err := s.Collector.InterfaceStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": stats})
}

func (s *Server) handleLeases(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	leases, err := s.Collector.Leases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": leases})
}

func (s *Server) handleARP(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	entries, err := s.Collector.ARP(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"arp": entries})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if s.Collector == nil {
		writeError(w, http.StatusServiceUnavailable, "сбор состояния недоступен")
		return
	}
	table := r.URL.Query().Get("table")
	routes, err := s.Collector.Routes(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	rules, err := s.Collector.Rules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "чтение policy rules: %v", err)
		return
	}
	parsed, err := s.Collector.ParsedRoutes(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "разбор маршрутов: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"routes": routes, "rules": rules, "parsed": parsed,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.Store.ListAudit(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// handleRender показывает, во что превращается конфигурация. Администратору
// важно видеть настоящие правила, а не верить на слово, что форма их составила
// правильно.
func (s *Server) handleRender(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentDraft()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}

	kind := r.PathValue("kind")
	if _, ok := render.ByID(kind); !ok {
		writeError(w, http.StatusNotFound, "неизвестный артефакт")
		return
	}
	content, err := render.Render(kind, cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(content))
}

// handleRenderList перечисляет артефакты, которые при текущей конфигурации
// действительно лежат на машине.
//
// Список приходит с сервера, а не зашит в панели: демоны выбирает
// администратор, и диагностика обязана показывать конфигурацию того, который
// работает. Зашитый список показывал dnsmasq даже там, где выбраны unbound и
// ISC DHCP, а самих unbound и ISC не показывал вовсе.
func (s *Server) handleRenderList(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentDraft()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация недоступна")
		return
	}
	type item struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	items := []item{}
	for _, a := range render.Active(cfg) {
		items = append(items, item{ID: a.ID, Title: a.Title})
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": items})
}

// uptimeSeconds читает время работы машины.
func uptimeSeconds() int64 {
	data, err := os.ReadFile(procUptimePath)
	if err != nil {
		return 0
	}
	var up float64
	if _, err := fmt.Sscanf(string(data), "%f", &up); err != nil {
		return 0
	}
	return int64(up)
}

var procUptimePath = "/proc/uptime"
