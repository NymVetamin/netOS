package firewall

import "testing"

func TestSubnetOfRejectsMalformedAddresses(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.129/24": "192.0.2.0/24",
		"0.0.0.0/0":      "0.0.0.0/0",
		"-1.0.0.1/24":    "-1.0.0.1/24",
		"192.0.2.1/99":   "192.0.2.1/99",
	} {
		if got := subnetOf(input); got != want {
			t.Errorf("subnetOf(%q) = %q, want %q", input, got, want)
		}
	}
}
