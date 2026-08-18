package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/subsys/services"
)

type ctxKey string

const ctxUser ctxKey = "user"

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

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser, username)))
	})
}

func userOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUser).(string); ok {
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
	Username   string `json:"username"`
	Role       string `json:"role"`
	CSRFToken  string `json:"csrf_token"`
	MustChange bool   `json:"must_change"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, blocked := s.loginBlocked(ip); blocked {
		writeError(w, http.StatusTooManyRequests,
			"слишком много неудачных попыток, повторите через %d секунд", int(wait.Seconds()))
		return
	}

	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный запрос")
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
	if err := s.Store.CreateSession(token, user.Username, ip, sessionTTL); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить сессию")
		return
	}

	s.csrfMu.Lock()
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
	_ = s.Store.Audit(store.AuditEntry{User: user.Username, Action: "login", SourceIP: ip, Success: true})

	writeJSON(w, http.StatusOK, loginResponse{
		Username:   user.Username,
		Role:       user.Role,
		CSRFToken:  csrf,
		MustChange: user.MustChange,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"username":    user.Username,
		"role":        user.Role,
		"must_change": user.MustChange,
		"last_login":  user.LastLogin,
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
	if len(req.New) < 10 {
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
	if err := s.Store.UpdatePassword(username, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить пароль")
		return
	}
	// Пароль сменён — файл с временными учётными данными больше не нужен и
	// не должен лежать на диске.
	_ = os.Remove("/var/lib/netos/initial-credentials")

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
	if !ok || time.Now().After(f.until) {
		return 0, false
	}
	return time.Until(f.until), true
}

// recordLoginFailure наращивает паузу после каждой неудачи: пять попыток
// проходят свободно, дальше задержка растёт до минуты.
func (s *Server) recordLoginFailure(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	f, ok := s.loginFails[ip]
	if !ok {
		f = &failCounter{}
		s.loginFails[ip] = f
	}
	f.count++
	if f.count > 5 {
		delay := time.Duration(f.count-5) * 10 * time.Second
		if delay > time.Minute {
			delay = time.Minute
		}
		f.until = time.Now().Add(delay)
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
func (s *Server) currentDraft() *config.Config {
	s.draftMu.RLock()
	if s.draft != nil {
		d := s.draft
		s.draftMu.RUnlock()
		return d
	}
	s.draftMu.RUnlock()
	return s.Engine.Current()
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
	Rollback *apply.RollbackInfo `json:"rollback,omitempty"`
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentDraft()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "конфигурация ещё не загружена")
		return
	}

	s.draftMu.RLock()
	dirty := s.draft != nil
	s.draftMu.RUnlock()

	pending, deadline := s.Engine.Pending()
	resp := configResponse{
		Config:   cfg,
		Dirty:    dirty,
		Problems: cfg.Validate().Problems,
		Pending:  pending,
		Rollback: s.Engine.LastRollback(),
	}
	if pending {
		resp.Deadline = &deadline
	}
	writeJSON(w, http.StatusOK, resp)
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

	s.draftMu.Lock()
	s.draft = &cfg
	s.draftMu.Unlock()

	writeJSON(w, http.StatusOK, configResponse{
		Config:   &cfg,
		Dirty:    true,
		Problems: result.Problems,
	})
}

func (s *Server) handleDiscard(w http.ResponseWriter, r *http.Request) {
	s.draftMu.Lock()
	s.draft = nil
	s.draftMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
	Comment string `json:"comment"`
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	_ = readJSON(r, &req)

	cfg := s.currentDraft()
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

	// Подтверждение требуется всегда, когда есть куда откатываться: именно оно
	// спасает администратора, закрывшего себе доступ правилом файрволла.
	result, err := s.Engine.Apply(r.Context(), cfg, revID, true)
	if err != nil {
		_ = s.Store.SetRevisionState(revID, store.StateRolledBack)
		_ = s.Store.Audit(store.AuditEntry{
			User: username, Action: "apply", Target: strconv.FormatInt(revID, 10),
			Detail: err.Error(), SourceIP: clientIP(r), Success: false,
		})
		writeError(w, http.StatusInternalServerError, "применение не удалось: %v", err)
		return
	}

	if !result.NeedsConfirm {
		if err := s.Store.MarkActive(revID); err != nil {
			s.Logger.Warnf("не удалось пометить ревизию активной: %v", err)
		}
		s.draftMu.Lock()
		s.draft = nil
		s.draftMu.Unlock()
	}

	_ = s.Store.Audit(store.AuditEntry{
		User: username, Action: "apply", Target: strconv.FormatInt(revID, 10),
		Detail: req.Comment, SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.Confirm(); err != nil {
		writeError(w, http.StatusConflict, "%v", err)
		return
	}

	// Подтверждённая конфигурация становится активной, черновик больше не нужен.
	cfg := s.Engine.Current()
	if latest, err := s.Store.LatestRevision(); err == nil && latest.Config != nil {
		_ = s.Store.MarkActive(latest.ID)
	}
	_ = cfg

	s.draftMu.Lock()
	s.draft = nil
	s.draftMu.Unlock()

	_ = s.Store.Audit(store.AuditEntry{
		User: userOf(r), Action: "confirm", SourceIP: clientIP(r), Success: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.Rollback(r.Context()); err != nil {
		writeError(w, http.StatusConflict, "%v", err)
		return
	}
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
	s.draft = rev.Config
	s.draftMu.Unlock()

	writeJSON(w, http.StatusOK, configResponse{
		Config:   rev.Config,
		Dirty:    true,
		Problems: rev.Config.Validate().Problems,
	})
}

// ---------------------------------------------------------------------------
// Наблюдение
// ---------------------------------------------------------------------------

// handleCatalog отдаёт список того, что netOS умеет устанавливать. Панель
// строит по нему раздел компонентов и подсказывает, чего не хватает для
// нужной функции.
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"components": config.Catalog})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Engine.Current()
	stats, _ := s.Collector.InterfaceStats()
	clients, _ := s.Collector.Clients(r.Context())

	online := 0
	for _, c := range clients {
		if c.Online {
			online++
		}
	}

	pending, deadline := s.Engine.Pending()
	resp := map[string]any{
		"hostname":         "",
		"uptime_seconds":   uptimeSeconds(),
		"interfaces":       stats,
		"clients_total":    len(clients),
		"clients_online":   online,
		"conntrack_count":  s.Collector.ConntrackCount(),
		"pending_confirm":  pending,
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
	clients, err := s.Collector.Clients(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	// Дополняем наблюдаемые устройства тем, что администратор о них задал:
	// именем, каналом, блокировкой.
	if cfg := s.Engine.Current(); cfg != nil {
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

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Collector.InterfaceStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": stats})
}

func (s *Server) handleLeases(w http.ResponseWriter, r *http.Request) {
	leases, err := s.Collector.Leases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": leases})
}

func (s *Server) handleARP(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Collector.ARP(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"arp": entries})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	routes, err := s.Collector.Routes(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	rules, _ := s.Collector.Rules(r.Context())
	parsed, _ := s.Collector.ParsedRoutes(r.Context(), table)
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

	var content string
	switch r.PathValue("kind") {
	case "iptables":
		rs, err := firewall.Build(cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "%v", err)
			return
		}
		content = rs.IPv4
		if rs.IPv6 != "" {
			content += "\n# --- ip6tables ---\n" + rs.IPv6
		}
	case "dnsmasq":
		content = services.NewDnsmasq(nil).Render(cfg)
	default:
		writeError(w, http.StatusNotFound, "неизвестный артефакт")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(content))
}

// uptimeSeconds читает время работы машины.
func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var up float64
	if _, err := fmt.Sscanf(string(data), "%f", &up); err != nil {
		return 0
	}
	return int64(up)
}
