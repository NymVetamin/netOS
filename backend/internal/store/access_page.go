package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ReadAccessAuditBatch returns at most 501 candidates in insertion order.
// maxID=-1 starts a snapshot; beforeID=0 includes its newest row.
// ErrNotFound means the consumed anchor was pruned and the page must restart.
func (s *Store) ReadAccessAuditBatch(ctx context.Context, maxID, beforeID int64) ([]AuditEntry, int64, error) {
	if maxID < -1 || beforeID < 0 || (maxID == -1 && beforeID != 0) || (maxID >= 0 && beforeID > maxID) {
		return nil, maxID, fmt.Errorf("неверная граница аудита")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, maxID, err
	}
	defer tx.Rollback()
	if maxID == -1 {
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit`).Scan(&maxID); err != nil {
			return nil, maxID, err
		}
	} else if beforeID != 0 {
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM audit WHERE id=? AND action IN ('login','logout')`, beforeID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, maxID, ErrNotFound
		}
		if err != nil {
			return nil, maxID, err
		}
	}
	query := `SELECT id,at,user,action,target,detail,source_ip,success FROM audit WHERE action IN ('login','logout') AND id<=?`
	args := []any{maxID}
	if beforeID != 0 {
		query += ` AND id<?`
		args = append(args, beforeID)
	}
	query += ` ORDER BY id DESC LIMIT 501`
	rows, err := tx.QueryContext(ctx, query, args...)
	entries, err := scanAuditRows(rows, err)
	if err != nil {
		return nil, maxID, err
	}
	if err = tx.Commit(); err != nil {
		return nil, maxID, err
	}
	return entries, maxID, nil
}
