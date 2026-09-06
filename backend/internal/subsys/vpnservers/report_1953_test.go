package vpnservers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

const nestedSAs = `list-sa event {netos-srv4 {uniqueid=7 version=2 state=ESTABLISHED remote-id=192.0.2.2 remote-eap-id=alice child-sas {netos-srv4-1 {uniqueid=1 state=INSTALLED}}}}
list-sa event {netos-srv4 {uniqueid=9 remote-id=192.0.2.3 remote-eap-id=bob child-sas {netos-srv4-2 {uniqueid=2}}}}`

func TestReport1953ParseNestedIKEv2SAs(t *testing.T) {
	want := []ikev2SA{{uniqueID: "7", identity: "alice"}, {uniqueID: "9", identity: "bob"}}
	if got := parseIKEv2SAs(nestedSAs); !reflect.DeepEqual(got, want) {
		t.Fatalf("SAs = %+v, want %+v", got, want)
	}
}

func TestReport1953TerminateOnlyRevokedIKE(t *testing.T) {
	_, server := ikev2TestConfig()
	var terminated []string
	s := &Subsystem{Runner: vpnRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		switch args[0] {
		case "is-active":
			return "active", nil
		case "--list-sas":
			return nestedSAs, nil
		case "--terminate":
			terminated = append(terminated, args[2])
			if args[2] != "9" {
				return "", fmt.Errorf("wrong IKE ID %s", args[2])
			}
		default:
			return "", fmt.Errorf("unexpected %s %s", name, strings.Join(args, " "))
		}
		return "", nil
	})}
	if err := s.terminateRevokedIKEv2(context.Background(), []config.VPNServer{server}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(terminated, []string{"9"}) {
		t.Fatalf("terminated %v", terminated)
	}
}

func TestReport1953TerminateDisconnectRace(t *testing.T) {
	for _, gone := range []bool{false, true} {
		t.Run(fmt.Sprint(gone), func(t *testing.T) {
			s := &Subsystem{Runner: vpnRunnerFunc(func(_ context.Context, _ string, args ...string) (string, error) {
				switch args[0] {
				case "is-active":
					return "active", nil
				case "--list-sas":
					return `list-sa event {netos-srv4 {uniqueid=9 remote-eap-id=bob}}`, nil
				case "--terminate":
					if gone {
						return "terminate failed: no matching SAs to terminate found", fmt.Errorf("exit status 1")
					}
					return "permission denied", fmt.Errorf("exit status 1")
				}
				return "", nil
			})}
			err := s.terminateRevokedIKEv2(context.Background(), nil)
			if (err == nil) != gone {
				t.Fatalf("gone=%v: %v", gone, err)
			}
		})
	}
}
