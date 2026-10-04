package manage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Multi-WAN source/oif rules and blackhole routes do not carry proto 201.
// Remove them using their persisted ownership before replacing the database.
func (m *Manager) removeOwnedMultiWAN(ctx context.Context) error {
	path := filepath.Join(m.StateDir, "generated", "multiwan-balance.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var indices []int
	if err := json.Unmarshal(data, &indices); err != nil {
		return err
	}
	for _, index := range indices {
		if index < 1 || index > 999 {
			return fmt.Errorf("invalid owned Multi-WAN index %d", index)
		}
	}
	rules, err := m.Output(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, index := range indices {
		if seen[index] {
			continue
		}
		seen[index] = true
		priority, table := strconv.Itoa(30000+index), strconv.Itoa(3000+index)
		for _, line := range strings.Split(rules, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != priority+":" {
				continue
			}
			owned := false
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "lookup" && fields[i+1] == table {
					owned = true
				}
			}
			if !owned {
				continue
			}
			parts := make([]string, 0, len(fields)-1)
			for _, field := range fields[1:] {
				if field != "[detached]" {
					parts = append(parts, field)
				}
			}
			args := append([]string{"-4", "rule", "del", "priority", priority}, parts...)
			if err := m.run(ctx, "ip", args...); err != nil {
				return err
			}
		}
		if err := m.run(ctx, "ip", "-4", "route", "flush", "table", table); err != nil {
			return err
		}
	}
	return nil
}
