package policy

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func canonicalEntries(entries []string) []string {
	seen := map[string]bool{}
	for _, raw := range entries {
		if a, err := netip.ParseAddr(raw); err == nil {
			seen[a.String()+"/32"] = true
		} else if p, err := netip.ParsePrefix(raw); err == nil {
			seen[p.Masked().String()] = true
		}
	}
	var out []string
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func setMembers(detail string) []string {
	_, members, _ := strings.Cut(detail, "Members:")
	var entries []string
	for _, line := range strings.Split(members, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			entries = append(entries, fields[0])
		}
	}
	return canonicalEntries(entries)
}

// Build off to the side, then swap atomically so an edited deny set never
// becomes briefly empty while live rules still reference it.
func (s *Subsystem) replaceStaticMembers(ctx context.Context, item ownedSet) error {
	temporary := item.Name + "-next"
	if _, err := s.Runner.Run(ctx, "ipset", "create", temporary, "hash:net", "family", "inet", "maxelem", "65536"); err != nil {
		return fmt.Errorf("create temporary address set: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = s.Runner.Run(cleanup, "ipset", "destroy", temporary)
	}()
	var input strings.Builder
	for _, entry := range item.Entries {
		fmt.Fprintf(&input, "add %s %s\n", temporary, entry)
	}
	if input.Len() > 0 {
		if _, err := s.Runner.RunInput(ctx, input.String(), "ipset", "restore"); err != nil {
			return err
		}
	}
	_, err := s.Runner.Run(ctx, "ipset", "swap", temporary, item.Name)
	return err
}
