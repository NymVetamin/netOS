package qos

import "strings"

// trafficBlocks indexes one tc response. It is never reused across OS reads.
type trafficBlocks struct {
	fields  [][]string
	byToken map[string][]int
}

func parseTrafficBlocks(output, boundary string) trafficBlocks {
	result := trafficBlocks{byToken: make(map[string][]int)}
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		fields := trafficFields(current.String())
		id := len(result.fields)
		for i, field := range fields {
			field = normalizeTrafficToken(field)
			fields[i] = field
			ids := result.byToken[field]
			if len(ids) == 0 || ids[len(ids)-1] != id {
				result.byToken[field] = append(ids, id)
			}
		}
		result.fields = append(result.fields, fields)
		current.Reset()
	}
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, boundary) {
			flush()
		}
		if trimmed != "" {
			current.WriteByte(' ')
			current.WriteString(trimmed)
		}
	}
	flush()
	return result
}

func (blocks trafficBlocks) hasTokens(tokens ...string) bool {
	if len(tokens) == 0 {
		return len(blocks.fields) > 0
	}
	conditions := make([][]string, len(tokens))
	var candidates []int
	for i, token := range tokens {
		parts := strings.SplitN(token, "=", 2)
		for j, part := range parts {
			parts[j] = normalizeTrafficToken(part)
			ids := blocks.byToken[parts[j]]
			if len(ids) == 0 {
				return false
			}
			if candidates == nil || len(ids) < len(candidates) {
				candidates = ids
			}
		}
		conditions[i] = parts
	}
	// A selective token (normally MAC or class ID) narrows the search, but
	// every condition must still match within that same block.
	for _, id := range candidates {
		fields := blocks.fields[id]
		matched := true
		for _, parts := range conditions {
			found := false
			for i, field := range fields {
				if field == parts[0] && (len(parts) == 1 || i+1 < len(fields) && fields[i+1] == parts[1]) {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
