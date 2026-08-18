// Package store хранит конфигурацию, учётные записи и журнал аудита в SQLite.
//
// Конфигурация versioned: каждое применение создаёт новую ревизию, активная
// ровно одна. Это даёт откат к любой точке, дифф между версиями и понятный
// журнал «кто что поменял».
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/netos-router/netos/internal/config"
	_ "modernc.org/sqlite" // чистый Go, без cgo — бинарник остаётся статическим
)

// Состояния ревизии.
const (
	StateDraft      = "draft"
	StateApplying   = "applying"
	StateActive     = "active"
	StateRolledBack = "rolled_back"
	StateSuperseded = "superseded"
)

var ErrNotFound = errors.New("не найдено")

type Store struct {
	db *sql.DB
}

// Revision — одна версия конфигурации.
type Revision struct {
	ID        int64          `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Author    string         `json:"author"`
	Comment   string         `json:"comment"`
	State     string         `json:"state"`
	AppliedAt *time.Time     `json:"applied_at,omitempty"`
	Config    *config.Config `json:"config,omitempty"`
}

// User — учётная запись веб-панели.
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"` // admin | viewer
	TOTPSecret   string     `json:"-"`
	MustChange   bool       `json:"must_change"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// AuditEntry — запись журнала действий.
type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	User     string    `json:"user"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Detail   string    `json:"detail"`
	SourceIP string    `json:"source_ip"`
	Success  bool      `json:"success"`
}

func Open(path string) (*Store, error) {
	// busy_timeout спасает от «database is locked», когда фоновые задачи
	// (сбор метрик, аренды DHCP) пишут одновременно с админом.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite плохо переносит параллельную запись из многих соединений.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("миграция БД: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    author     TEXT NOT NULL DEFAULT '',
    comment    TEXT NOT NULL DEFAULT '',
    config     TEXT NOT NULL,
    state      TEXT NOT NULL,
    applied_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_revisions_state ON revisions(state);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    totp_secret   TEXT NOT NULL DEFAULT '',
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER
);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    user      TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    success   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    source_ip  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Наблюдаемые устройства: накапливаются автоматически из аренд DHCP и ARP,
-- живут отдельно от конфигурации, чтобы не раздувать ревизии.
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    vendor     TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    rx_bytes   INTEGER NOT NULL DEFAULT 0,
    tx_bytes   INTEGER NOT NULL DEFAULT 0
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err := s.db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, config.Version)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Ревизии
// ---------------------------------------------------------------------------

// CreateRevision сохраняет конфигурацию как черновик.
func (s *Store) CreateRevision(cfg *config.Config, author, comment string) (int64, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(
		`INSERT INTO revisions (created_at, author, comment, config, state) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), author, comment, string(data), StateDraft)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MarkActive помечает ревизию активной, а предыдущую активную — устаревшей.
// Выполняется одной транзакцией: две активные ревизии сломали бы восстановление
// конфигурации при загрузке.
func (s *Store) MarkActive(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE revisions SET state = ? WHERE state = ?`, StateSuperseded, StateActive); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE revisions SET state = ?, applied_at = ? WHERE id = ?`,
		StateActive, time.Now().Unix(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetRevisionState(id int64, state string) error {
	_, err := s.db.Exec(`UPDATE revisions SET state = ? WHERE id = ?`, state, id)
	return err
}

// ActiveRevision возвращает применённую сейчас конфигурацию. Используется при
// старте демона для восстановления состояния системы.
func (s *Store) ActiveRevision() (*Revision, error) {
	return s.revisionWhere(`state = ?`, StateActive)
}

func (s *Store) Revision(id int64) (*Revision, error) {
	return s.revisionWhere(`id = ?`, id)
}

// LatestRevision возвращает самую свежую ревизию независимо от состояния —
// это то, что админ редактирует в панели.
func (s *Store) LatestRevision() (*Revision, error) {
	return s.revisionWhere(`1 = 1 ORDER BY id DESC`, )
}

func (s *Store) revisionWhere(where string, args ...any) (*Revision, error) {
	query := `SELECT id, created_at, author, comment, config, state, applied_at FROM revisions WHERE ` + where + ` LIMIT 1`
	row := s.db.QueryRow(query, args...)

	var r Revision
	var createdAt int64
	var appliedAt sql.NullInt64
	var raw string

	if err := row.Scan(&r.ID, &createdAt, &r.Author, &r.Comment, &raw, &r.State, &appliedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.CreatedAt = time.Unix(createdAt, 0)
	if appliedAt.Valid {
		t := time.Unix(appliedAt.Int64, 0)
		r.AppliedAt = &t
	}

	var cfg config.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("разбор конфигурации ревизии %d: %w", r.ID, err)
	}
	cfg.Normalize()
	r.Config = &cfg
	return &r, nil
}

// ListRevisions возвращает историю без тел конфигураций — панель показывает
// список, а тело подгружает по требованию.
func (s *Store) ListRevisions(limit int) ([]Revision, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, created_at, author, comment, state, applied_at FROM revisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Revision
	for rows.Next() {
		var r Revision
		var createdAt int64
		var appliedAt sql.NullInt64
		if err := rows.Scan(&r.ID, &createdAt, &r.Author, &r.Comment, &r.State, &appliedAt); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(createdAt, 0)
		if appliedAt.Valid {
			t := time.Unix(appliedAt.Int64, 0)
			r.AppliedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneRevisions удаляет старые ревизии, оставляя последние keep штук.
// Активная и та, что стала бы целью отката, не трогаются никогда.
func (s *Store) PruneRevisions(keep int) error {
	if keep < 5 {
		keep = 5
	}
	_, err := s.db.Exec(`
        DELETE FROM revisions
        WHERE state NOT IN (?, ?)
          AND id NOT IN (SELECT id FROM revisions ORDER BY id DESC LIMIT ?)`,
		StateActive, StateApplying, keep)
	return err
}

// ---------------------------------------------------------------------------
// Пользователи
// ---------------------------------------------------------------------------

func (s *Store) CreateUser(username, passwordHash, role string, mustChange bool) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role, must_change, created_at) VALUES (?, ?, ?, ?, ?)`,
		username, passwordHash, role, boolToInt(mustChange), time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UserByName(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role, totp_secret, must_change, created_at, last_login
         FROM users WHERE username = ?`, username)

	var u User
	var createdAt int64
	var lastLogin sql.NullInt64
	var mustChange int

	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.TOTPSecret,
		&mustChange, &createdAt, &lastLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.MustChange = mustChange != 0
	u.CreatedAt = time.Unix(createdAt, 0)
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		u.LastLogin = &t
	}
	return &u, nil
}

func (s *Store) UpdatePassword(username, passwordHash string) error {
	_, err := s.db.Exec(
		`UPDATE users SET password_hash = ?, must_change = 0 WHERE username = ?`, passwordHash, username)
	return err
}

func (s *Store) TouchLogin(username string) error {
	_, err := s.db.Exec(`UPDATE users SET last_login = ? WHERE username = ?`, time.Now().Unix(), username)
	return err
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------------------
// Сессии
// ---------------------------------------------------------------------------

func (s *Store) CreateSession(token, username, sourceIP string, ttl time.Duration) error {
	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, username, created_at, expires_at, source_ip) VALUES (?, ?, ?, ?, ?)`,
		token, username, now.Unix(), now.Add(ttl).Unix(), sourceIP)
	return err
}

// SessionUser возвращает владельца живой сессии. Просроченные сессии не
// возвращаются, даже если ещё лежат в таблице.
func (s *Store) SessionUser(token string) (string, error) {
	var username string
	var expires int64
	err := s.db.QueryRow(
		`SELECT username, expires_at FROM sessions WHERE token = ?`, token).Scan(&username, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if time.Now().Unix() > expires {
		return "", ErrNotFound
	}
	return username, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (s *Store) PruneSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}

// ---------------------------------------------------------------------------
// Аудит
// ---------------------------------------------------------------------------

func (s *Store) Audit(e AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit (at, user, action, target, detail, source_ip, success) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(), e.User, e.Action, e.Target, e.Detail, e.SourceIP, boolToInt(e.Success))
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, at, user, action, target, detail, source_ip, success FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		var success int
		if err := rows.Scan(&e.ID, &at, &e.User, &e.Action, &e.Target, &e.Detail, &e.SourceIP, &success); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		e.Success = success != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Устройства
// ---------------------------------------------------------------------------

// UpsertDevice фиксирует факт, что устройство видели в сети.
func (s *Store) UpsertDevice(mac, ip, hostname string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
        INSERT INTO devices (mac, ip, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            ip = excluded.ip,
            hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
            last_seen = excluded.last_seen`,
		mac, ip, hostname, now, now)
	return err
}

type Device struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	RXBytes   int64     `json:"rx_bytes"`
	TXBytes   int64     `json:"tx_bytes"`
}

func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(
		`SELECT mac, ip, hostname, vendor, first_seen, last_seen, rx_bytes, tx_bytes FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		var first, last int64
		if err := rows.Scan(&d.MAC, &d.IP, &d.Hostname, &d.Vendor, &first, &last, &d.RXBytes, &d.TXBytes); err != nil {
			return nil, err
		}
		d.FirstSeen = time.Unix(first, 0)
		d.LastSeen = time.Unix(last, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Ping проверяет живость соединения с БД — используется health-check'ом панели.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
