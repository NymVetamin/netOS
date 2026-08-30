package bootstrap

import "testing"

func TestSubnetOf(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.129/24": "192.0.2.0/24",
		"0.0.0.0/0":      "0.0.0.0/0",
		"192.0.2.1/99":   "192.0.2.1/99",
		"999.0.0.1/24":   "999.0.0.1/24",
		"2001:db8::1/64": "2001:db8::1/64",
	} {
		if got := subnetOf(input); got != want {
			t.Errorf("subnetOf(%q) = %q, want %q", input, got, want)
		}
	}
}
