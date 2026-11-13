package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// LogoutSession revokes one session together with its durable access event.
// A concurrent retry that finds no session must not create a second event.
func (s *Store) LogoutSession(ctx context.Context, token, sourceIP string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username string
	err = tx.QueryRowContext(ctx, `DELETE FROM sessions WHERE token = ? RETURNING username`, token).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(at,user,action,source_ip,success) VALUES(?,?,'logout',?,1)`, time.Now().Unix(), username, sourceIP); err != nil {
		return err
	}
	return tx.Commit()
}
