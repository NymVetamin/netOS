package system

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type planReadsKey struct{}

// WithPlanUnitReads scopes read reuse to one read-only plan. Do not pass the
// returned context into Apply/Health: those must observe their own mutations.
// A new scope is created even if the caller supplied a previous plan context.
func WithPlanUnitReads(ctx context.Context) context.Context {
	return context.WithValue(ctx, planReadsKey{}, &planUnitReads{runners: make(map[*Exec]*unitReads)})
}

type planUnitReads struct {
	mu      sync.Mutex
	runners map[*Exec]*unitReads
}

type unitReads struct {
	loaded  bool
	active  map[string]string
	success map[string]string
}

func literalUnit(unit string) bool {
	return unit != "" && !strings.HasPrefix(unit, "-") &&
		!strings.ContainsAny(unit, "*?[]/ \t\r\n\x00") &&
		(strings.HasSuffix(unit, ".service") || strings.HasSuffix(unit, ".socket"))
}

// planUnitRead only recognizes the exact read commands used by the planners.
// Other commands, aliases absent from the snapshot, missing units, transitional
// states and failed probes keep the original systemctl path and diagnostics.
func (e *Exec) planUnitRead(ctx context.Context, args []string) (string, error, bool) {
	scope, ok := ctx.Value(planReadsKey{}).(*planUnitReads)
	if !ok {
		return "", nil, false
	}
	active := len(args) == 2 && args[0] == "is-active" && literalUnit(args[1])
	enabled := len(args) == 2 && args[0] == "is-enabled" && literalUnit(args[1])
	present := len(args) == 3 && args[0] == "list-unit-files" && args[1] == "--no-legend" && literalUnit(args[2])
	if !active && !enabled && !present {
		return "", nil, false
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err, true
	}
	r := scope.runners[e]
	if r == nil {
		r = &unitReads{success: make(map[string]string)}
		scope.runners[e] = r
	}
	if active {
		if !r.loaded {
			r.loaded = true
			out, err := e.runInput(ctx, "", "systemctl", "list-units", "--all", "--type=service,socket", "--no-legend", "--plain", "--no-pager")
			if err == nil {
				r.active = make(map[string]string)
				for _, line := range strings.Split(out, "\n") {
					f := strings.Fields(line)
					if len(f) >= 4 && f[1] == "loaded" {
						r.active[f[0]] = f[2]
					}
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return "", err, true
		}
		switch state := r.active[args[1]]; state {
		case "active":
			return state + "\n", nil, true
		case "inactive", "failed":
			return state + "\n", fmt.Errorf("systemctl is-active %s: exit status 3: %s", args[1], state), true
		}
		// Do not memoize fallback active probes: a transitional state must not
		// become a stable snapshot entry merely because systemctl succeeded.
		out, err := e.runInput(ctx, "", "systemctl", args...)
		return out, err, true
	}
	key := strings.Join(args, "\x00")
	if out, ok := r.success[key]; ok {
		return out, nil, true
	}
	out, err := e.runInput(ctx, "", "systemctl", args...)
	if err == nil {
		r.success[key] = out
	}
	return out, err, true
}
