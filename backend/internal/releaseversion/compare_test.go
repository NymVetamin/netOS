package releaseversion

import "testing"

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		want  int
		known bool
	}{
		{"v0.09", "v0.10", -1, true}, {"v0.12", "0.12.0", 0, true}, {"v0.12", "v0.9", 1, true},
		{"dev", "v0.12", 0, false}, {"v0.12-rc1", "v0.12", 0, false},
	} {
		got, known := Compare(c.a, c.b)
		if got != c.want || known != c.known {
			t.Fatalf("%+v: %d %v", c, got, known)
		}
	}
}
