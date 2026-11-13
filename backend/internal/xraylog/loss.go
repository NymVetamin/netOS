package xraylog

import (
	"regexp"
	"strconv"
	"strings"
)

type Loss struct{ Count, Oversized, Resources uint64 }

var lossDetail = regexp.MustCompile(`^([0-9]+) messages \(oversized=([0-9]+), resources=([0-9]+)\)$`)

// ParseLoss distinguishes missing resource detail from diagnostic-only losses.
func ParseLoss(message string) (Loss, bool) {
	tail, ok := strings.CutPrefix(message, LossPrefix)
	if !ok {
		return Loss{}, false
	}
	m := lossDetail.FindStringSubmatch(tail)
	if m == nil {
		return Loss{}, false
	}
	var values [3]uint64
	for i := range values {
		v, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return Loss{}, false
		}
		values[i] = v
	}
	l := Loss{values[0], values[1], values[2]}
	return l, l.Count > 0 && l.Oversized <= l.Resources && l.Resources <= l.Count
}
