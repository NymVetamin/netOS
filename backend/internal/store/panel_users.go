package store

import (
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

// SavePanelUser atomically changes access, revokes sessions and records the actor.
// Empty passwordHash preserves an existing credential; create requires a hash.
func (s *Store) SavePanelUser(u PanelUser, passwordHash string, create, remove bool, actor, sourceIP string) error {
	if u.Permissions == nil {
		u.Permissions = map[string]string{}
	}
	raw, err := json.Marshal(u.Permissions)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if create {
		if passwordHash == "" {
			return errors.New("задайте пароль")
		}
		if _, err = tx.Exec(`INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)`, u.Username, passwordHash, u.Role, time.Now().Unix()); err != nil {
			return err
		}
	} else {
		var exists int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, u.Username).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return ErrNotFound
		}
		if remove {
			_, err = tx.Exec(`DELETE FROM users WHERE username=?`, u.Username)
		} else {
			_, err = tx.Exec(`UPDATE users SET role=?,password_hash=CASE WHEN ?='' THEN password_hash ELSE ? END WHERE username=?`, u.Role, passwordHash, passwordHash, u.Username)
		}
		if err != nil {
			return err
		}
	}
	if remove {
		_, err = tx.Exec(`DELETE FROM panel_access WHERE username=?`, u.Username)
	} else {
		_, err = tx.Exec(`INSERT INTO panel_access(username,enabled,permissions) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET enabled=excluded.enabled,permissions=excluded.permissions`, u.Username, u.Enabled, string(raw))
	}
	if err != nil {
		return err
	}
	var admins int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM users u JOIN panel_access a ON a.username=u.username WHERE u.role='admin' AND a.enabled=1`).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return ErrLastAdmin
	}
	if _, err = tx.Exec(`DELETE FROM sessions WHERE username=?`, u.Username); err != nil {
		return err
	}
	action := "panel_user_update"
	if create {
		action = "panel_user_create"
	}
	if remove {
		action = "panel_user_delete"
	}
	if _, err = tx.Exec(`INSERT INTO audit(at,user,action,target,detail,source_ip,success) VALUES(?,?,?,?,?,?,1)`, time.Now().Unix(), actor, action, u.Username, fmt.Sprintf("role=%s enabled=%t permissions=%s", u.Role, u.Enabled, raw), sourceIP); err != nil {
		return err
	}
	return tx.Commit()
}
