package api

import (
	"cmp"
	"database/sql"
	"fmt"
	"slices"
)

// Block identity follows insertion order, including when wall time repeats.
const createHistoryBlocks = `CREATE TABLE seconds(id INTEGER PRIMARY KEY,start REAL NOT NULL,finish REAL NOT NULL,data BLOB NOT NULL,summary BLOB NOT NULL)`

func prepareSecondHistory(db *sql.DB) (int64, error) {
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000"); err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var columns, ids int
	if err = tx.QueryRow("SELECT count(*), count(CASE WHEN name='id' THEN 1 END) FROM pragma_table_info('seconds')").Scan(&columns, &ids); err != nil {
		return 0, err
	}
	switch {
	case columns == 0:
		_, err = tx.Exec(createHistoryBlocks)
	case ids == 0:
		err = migrateHistoryBlocks(tx)
	}
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec("CREATE INDEX IF NOT EXISTS seconds_finish ON seconds(finish); CREATE INDEX IF NOT EXISTS seconds_start ON seconds(start)"); err != nil {
		return 0, err
	}
	var next int64
	if err = tx.QueryRow("SELECT coalesce(max(id),0)+1 FROM seconds").Scan(&next); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

func migrateHistoryBlocks(tx *sql.Tx) error {
	if _, err := tx.Exec("ALTER TABLE seconds RENAME TO old_seconds"); err != nil {
		return err
	}
	if _, err := tx.Exec(createHistoryBlocks); err != nil {
		return err
	}
	// Return copied pages to SQLite before writing the next batch. The outer
	// transaction still restores the complete old table on any error.
	for {
		last, err := copyLegacyHistoryBatch(tx)
		if err != nil {
			return err
		}
		if last == 0 {
			break
		}
		if _, err = tx.Exec("DELETE FROM old_seconds WHERE rowid<=?", last); err != nil {
			return err
		}
	}
	_, err := tx.Exec("DROP TABLE old_seconds")
	return err
}

func copyLegacyHistoryBatch(tx *sql.Tx) (int64, error) {
	rows, err := tx.Query("SELECT rowid,data,summary FROM old_seconds ORDER BY rowid LIMIT 128")
	if err != nil {
		return 0, err
	}
	var last int64
	defer rows.Close()
	for rows.Next() {
		var id int64
		var data, summary []byte
		if err := rows.Scan(&id, &data, &summary); err != nil {
			return 0, err
		}
		// The old first/last bounds can both look valid while hiding an interior
		// sample. Inspect each old block once, in the schema migration transaction.
		type timestamp struct{ At float64 }
		stamps, err := decodeHistoryBlock[timestamp](data)
		if err != nil {
			return 0, fmt.Errorf("history block %d: %w", id, err)
		}
		if len(stamps) == 0 {
			return 0, fmt.Errorf("empty history block %d", id)
		}
		last = id
		if len(stamps) <= secondsPerBlock && stamps[len(stamps)-1].At-stamps[0].At < secondsPerBlock && slices.IsSortedFunc(stamps, func(a, b timestamp) int { return cmp.Compare(a.At, b.At) }) {
			_, err = tx.Exec("INSERT INTO seconds(start,finish,data,summary) VALUES(?,?,?,?)", stamps[0].At, stamps[len(stamps)-1].At, data, summary)
			if err != nil {
				return 0, err
			}
			continue
		}
		frames, err := decodeHistoryBlock[realtimeSnapshot](data)
		if err != nil {
			return 0, err
		}
		slices.SortStableFunc(frames, compareHistoryTime)
		for len(frames) > 0 {
			n := 1
			for n < len(frames) && n < secondsPerBlock && frames[n].At-frames[0].At < secondsPerBlock {
				n++
			}
			data, summary, err = encodeHistoryBlock(frames[:n])
			if err != nil {
				return 0, err
			}
			if _, err = tx.Exec("INSERT INTO seconds(start,finish,data,summary) VALUES(?,?,?,?)", frames[0].At, frames[n-1].At, data, summary); err != nil {
				return 0, err
			}
			frames = frames[n:]
		}
	}
	return last, rows.Err()
}
