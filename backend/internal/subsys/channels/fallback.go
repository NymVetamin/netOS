package channels

import "github.com/netos-router/netos/internal/config"

// Zero is a blocked route; direct removes the channel rule instead.
type fallbackRoute struct {
	table  int
	direct bool
}

// A resolver belongs to one fixed health snapshot. It caches destinations, not
// kernel rules: every channel must still reconcile its own rule and UDP flows.
type fallbackResolver struct {
	channels map[string]*config.Channel
	states   map[string]*channelState
	memo     map[string]fallbackRoute
	visiting map[string]bool
}

func newFallbackResolver(cfg *config.Config, states map[string]*channelState) *fallbackResolver {
	r := &fallbackResolver{
		channels: map[string]*config.Channel{}, states: states,
		memo: map[string]fallbackRoute{}, visiting: map[string]bool{},
	}
	for i := range cfg.Channels {
		ch := &cfg.Channels[i]
		if !ch.Enabled {
			continue
		}
		if _, exists := r.channels[ch.ID]; exists {
			// Invalid configurations can contain ambiguous roots. Preserve the
			// first enabled lookup and per-walk cycle detection without caching.
			r.memo = nil
			continue
		}
		r.channels[ch.ID] = ch
	}
	return r
}

func (r *fallbackResolver) resolve(ch config.Channel) fallbackRoute {
	if r.visiting[ch.ID] {
		return fallbackRoute{}
	}
	if route, ok := r.memo[ch.ID]; ok {
		return route
	}
	r.visiting[ch.ID] = true
	var route fallbackRoute
	switch ch.FailMode {
	case "direct":
		route.direct = true
	case "fallback":
		if next, ok := r.channels[ch.Fallback]; ok {
			if next.Type == "direct" {
				route.direct = true
			} else if state := r.states[next.ID]; state != nil && state.Down {
				route = r.resolve(*next)
			} else {
				route.table = TableNumber(*next)
			}
		}
	}
	delete(r.visiting, ch.ID)
	if r.memo != nil {
		r.memo[ch.ID] = route
	}
	return route
}
