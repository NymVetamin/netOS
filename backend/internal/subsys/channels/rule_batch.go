package channels

import (
	"context"
	"strings"
)

// One Apply can reuse a dump until the first rule change. Multiple rules at
// the same priority are legal and must all participate in matching.
type ruleBatch struct {
	watch      ruleWatch
	byPriority map[string][]string
	disabled   bool
}

func (b *ruleBatch) lines(ctx context.Context, s *Subsystem, priority string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b != nil && b.byPriority != nil {
		if b.watch.unchanged() {
			return b.byPriority[priority], nil
		}
		b.byPriority = nil
		b.disabled = true
	}
	out, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return nil, err
	}
	if b == nil || b.disabled {
		return strings.Split(out, "\n"), nil
	}
	b.byPriority = make(map[string][]string)
	for line := range strings.SplitSeq(out, "\n") {
		if key, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			b.byPriority[key] = append(b.byPriority[key], line)
		}
	}
	return b.byPriority[priority], nil
}
