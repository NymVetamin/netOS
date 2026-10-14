package releaseversion

import (
	"regexp"
	"strconv"
	"strings"
)

var stable = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){1,3}$`)

// Compare accepts stable numeric release tags, including historical v0.06.
func Compare(a, b string) (int, bool) {
	if !stable.MatchString(a) || !stable.MatchString(b) {
		return 0, false
	}
	x, y := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(x) || i < len(y); i++ {
		var n, m uint64
		var err error
		if i < len(x) {
			n, err = strconv.ParseUint(x[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if i < len(y) {
			m, err = strconv.ParseUint(y[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if n > m {
			return 1, true
		}
		if n < m {
			return -1, true
		}
	}
	return 0, true
}
