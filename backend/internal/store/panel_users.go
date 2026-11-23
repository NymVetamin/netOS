package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PanelAccess is separate from Samba identities and configuration revisions.
type PanelAccess struct {
	Enabled     bool              `json:"enabled"`
	Permissions map[string]string `json:"permissions"`
}

var ErrLastAdmin = errors.New("нельзя удалить или отключить последнего администратора")

func (s *Store) PanelAccess(username string) (PanelAccess, error) {
	access := PanelAccess{Enabled: true, Permissions: map[string]string{}}
	var raw string
	err := s.db.QueryRow(`SELECT enabled, permissions FROM panel_access WHERE username = ?`, username).Scan(&access.Enabled, &raw)
	if err != nil {
		return access, err
	}
	err = json.Unmarshal([]byte(raw), &access.Permissions)
	return access, err
}

type PanelUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	PanelAccess
}

func (s *Store) PanelUsers() ([]PanelUser, error) {
	rows, err := s.db.Query(`SELECT u.username,u.role,a.enabled,a.permissions FROM users u JOIN panel_access a ON a.username=u.username ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []PanelUser{}
	for rows.Next() {
		var u PanelUser
		var raw string
		if err := rows.Scan(&u.Username, &u.Role, &u.Enabled, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &u.Permissions); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// samePanelPermissions compares stored grants; a missing section has no access.
func samePanelPermissions(stored string, requested map[string]string) bool {
	var previous map[string]string
	if err := json.Unmarshal([]byte(stored), &previous); err != nil {
		return false
	}
	for section, level := range requested {
		old, ok := previous[section]
		if old != level && (ok || level != "none") {
			return false
		}
		delete(previous, section)
	}
	for _, level := range previous {
		if level != "none" {
			return false
		}
	}
	return true
}

// SavePanelUser atomically changes access, revokes sessions and records the actor.
// Empty passwordHash preserves an existing credential; create requires a hash.
func (s *Store) SavePanelUser(u PanelUser, passwordHash string, create, remove bool, actor, sourceIP string) (bool, error) {
	if u.Permissions == nil {
		u.Permissions = map[string]string{}
	}
	raw, err := json.Marshal(u.Permissions)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	changed := true
	if create {
		if passwordHash == "" {
			return false, errors.New("задайте пароль")
		}
		if _, err = tx.Exec(`INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)`, u.Username, passwordHash, u.Role, time.Now().Unix()); err != nil {
			return false, err
		}
	} else {
		var role, stored string
		var enabled bool
		err = tx.QueryRow(`SELECT u.role,COALESCE(a.enabled,0),COALESCE(a.permissions,'') FROM users u
   LEFT JOIN panel_access a ON a.username=u.username WHERE u.username=?`, u.Username).Scan(&role, &enabled, &stored)
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		changed = remove || passwordHash != "" || role != u.Role || enabled != u.Enabled ||
			(stored != string(raw) && !samePanelPermissions(stored, u.Permissions))
		if remove {
			_, err = tx.Exec(`DELETE FROM users WHERE username=?`, u.Username)
		} else if changed {
			_, err = tx.Exec(`UPDATE users SET role=?,password_hash=CASE WHEN ?='' THEN password_hash ELSE ? END WHERE username=?`, u.Role, passwordHash, passwordHash, u.Username)
		}
		if err != nil {
			return false, err
		}
	}
	if remove {
		_, err = tx.Exec(`DELETE FROM panel_access WHERE username=?`, u.Username)
	} else if changed {
		_, err = tx.Exec(`INSERT INTO panel_access(username,enabled,permissions) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET enabled=excluded.enabled,permissions=excluded.permissions`, u.Username, u.Enabled, string(raw))
	}
	if err != nil {
		return false, err
	}
	var admins int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM users u JOIN panel_access a ON a.username=u.username WHERE u.role='admin' AND a.enabled=1`).Scan(&admins); err != nil {
		return false, err
	}
	if admins == 0 {
		return false, ErrLastAdmin
	}
	if changed {
		if _, err = tx.Exec(`DELETE FROM sessions WHERE username=?`, u.Username); err != nil {
			return false, err
		}
	}
	action := "panel_user_update"
	if create {
		action = "panel_user_create"
	}
	if remove {
		action = "panel_user_delete"
	}
	if _, err = tx.Exec(`INSERT INTO audit(at,user,action,target,detail,source_ip,success) VALUES(?,?,?,?,?,?,1)`, time.Now().Unix(), actor, action, u.Username, fmt.Sprintf("role=%s enabled=%t permissions=%s", u.Role, u.Enabled, raw), sourceIP); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed, nil
}
