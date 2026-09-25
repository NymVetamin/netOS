package manage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/store"
)

func singleLine(value string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

// auditLogs reads the same audit table as the panel's History page. The
// technical systemd journal remains available through netos logs --system.
func (m *Manager) auditLogs(ctx context.Context, follow bool) error {
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		return fmt.Errorf("открытие журнала действий: %w", err)
	}
	defer st.Close()

	printEntries := func(entries []store.AuditEntry) error {
		for _, entry := range entries {
			result := "OK"
			if !entry.Success {
				result = "FAIL"
			}
			if _, err := fmt.Fprintf(m.Out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				entry.At.Format(time.RFC3339), singleLine(entry.User), singleLine(entry.Action), singleLine(entry.Target),
				result, singleLine(entry.SourceIP), singleLine(entry.Detail)); err != nil {
				return err
			}
		}
		return nil
	}
	entries, err := st.ListAudit(100)
	if err != nil {
		return fmt.Errorf("чтение журнала действий: %w", err)
	}
	if err := printEntries(entries); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	lastID := int64(0)
	if len(entries) > 0 {
		lastID = entries[0].ID
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			entries, err := st.ListAudit(100)
			if err != nil {
				return fmt.Errorf("чтение журнала действий: %w", err)
			}
			for i := len(entries) - 1; i >= 0; i-- {
				if entries[i].ID > lastID {
					if err := printEntries(entries[i : i+1]); err != nil {
						return err
					}
				}
			}
			if len(entries) > 0 && entries[0].ID > lastID {
				lastID = entries[0].ID
			}
		}
	}
}
