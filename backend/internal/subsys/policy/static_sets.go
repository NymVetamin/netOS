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
	var input strings.Builder
	for _, entry := range item.Entries {
		fmt.Fprintf(&input, "add %s-next %s\n", item.Name, entry)
	}
	return s.swapStaticSet(ctx, item.Name, []string{"hash:net", "family", "inet", "maxelem", "65536"}, input.String())
}

func (s *Subsystem) restoreStaticSet(ctx context.Context, name, snapshot string) error {
	header, members, _ := strings.Cut(snapshot, "\n")
	options, ok := strings.CutPrefix(header, "create "+name+" ")
	if !ok {
		return fmt.Errorf("invalid ipset snapshot header for %s", name)
	}
	var input strings.Builder
	for line := range strings.SplitSeq(strings.TrimSuffix(members, "\n"), "\n") {
		if line == "" {
			continue
		}
		entry, ok := strings.CutPrefix(line, "add "+name+" ")
		if !ok {
			return fmt.Errorf("invalid ipset snapshot entry for %s", name)
		}
		fmt.Fprintf(&input, "add %s-next %s\n", name, entry)
	}
	return s.swapStaticSet(ctx, name, strings.Fields(options), input.String())
}

func (s *Subsystem) swapStaticSet(ctx context.Context, name string, options []string, input string) error {
	temporary := name + "-next"
	if _, err := s.Runner.Run(ctx, "ipset", append([]string{"create", temporary}, options...)...); err != nil {
		return fmt.Errorf("create temporary address set: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = s.Runner.Run(cleanup, "ipset", "destroy", temporary)
	}()
	if input != "" {
		if _, err := s.Runner.RunInput(ctx, input, "ipset", "restore"); err != nil {
			return err
		}
	}
	_, err := s.Runner.Run(ctx, "ipset", "swap", temporary, name)
	return err
}
