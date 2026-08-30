package runtime

import "testing"

func TestInterfaceIsUpHandlesTunOperstate(t *testing.T) {
	tests := []struct {
		name      string
		operstate string
		flags     string
		want      bool
	}{
		{name: "ethernet up", operstate: "up", flags: "0x1003", want: true},
		{name: "ethernet no carrier", operstate: "down", flags: "0x1003", want: false},
		{name: "tun running", operstate: "unknown", flags: "0x1041", want: true},
		{name: "tun disabled", operstate: "unknown", flags: "0x1040", want: false},
		{name: "broken flags", operstate: "unknown", flags: "invalid", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := interfaceIsUp(tc.operstate, tc.flags); got != tc.want {
				t.Fatalf("interfaceIsUp(%q, %q) = %v, want %v", tc.operstate, tc.flags, got, tc.want)
			}
		})
	}
}
