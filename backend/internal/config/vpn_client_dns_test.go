package config

import (
	"reflect"
	"testing"
)

func TestVPNClientDNSPreservesRouterAddressSemantics(t *testing.T) {
	for _, tc := range []struct{ kind, subnet, want string }{{"l2tp", "10.9.0.17/24", "10.9.0.17"}, {"ikev2", "10.9.0.17/24", "10.9.0.17"}, {"ocserv", "10.9.0.17/24", "10.9.0.1"}, {"ocserv", "10.9.0.3/31", "10.9.0.2"}} {
		s := VPNServer{Type: tc.kind, Subnet: tc.subnet}
		custom := []string{"9.9.9.9", "1.1.1.1"}
		if got := s.ClientDNS(true, custom); !reflect.DeepEqual(got, []string{tc.want}) {
			t.Fatalf("%+v: %v", tc, got)
		}
		if got := s.ClientDNS(false, custom); !reflect.DeepEqual(got, []string{"9.9.9.9", "1.1.1.1"}) {
			t.Fatal("manual list changed")
		}
	}
}
