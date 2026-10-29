package config

import "testing"

func TestL2TPDefaultListenerAndLegacyBinding(t *testing.T) {
	for _, tc := range []struct {
		saved any
		want  string
	}{{nil, "0.0.0.0"}, {"0.0.0.0", "0.0.0.0"}, {"192.168.20.1", "192.168.20.1"}} {
		s := VPNServer{Type: "l2tp", Config: map[string]any{}}
		if tc.saved != nil {
			s.Config["listen"] = tc.saved
		}
		got, err := s.L2TPConfig()
		if err != nil || got.Listen != tc.want {
			t.Fatalf("%+v %v", got, err)
		}
		if tc.saved == nil && len(s.Config) != 0 {
			t.Fatal("decoder modified saved config")
		}
	}
}
