package netiface

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPermanentAddressRejectsExpiringLease(t *testing.T) {
	const address = "198.18.0.2/24"
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"missing", "", false},
		{"permanent", "2: eth1 inet 198.18.0.2/24 scope global eth1 valid_lft forever preferred_lft forever", true},
		{"dynamic", "2: eth1 inet 198.18.0.2/24 scope global dynamic eth1 valid_lft 81sec preferred_lft 81sec", false},
		{"finite lifetime", "2: eth1 inet 198.18.0.2/24 scope global eth1 valid_lft 81sec preferred_lft 81sec", false},
		{"other address", "2: eth1 inet 198.18.0.22/24 scope global eth1 valid_lft forever", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := permanentAddress(tc.output, address); got != tc.want {
				t.Fatalf("permanentAddress = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExplicitMTURestoresOriginalAcrossRestart(t *testing.T) {
	mtu := 8942
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.HasPrefix(command, "ip -o link show dev eth5") {
			return "7: eth5: <BROADCAST,UP> mtu " + fmt.Sprint(mtu), nil
		}
		if strings.HasPrefix(command, "ip link set eth5 mtu ") {
			_, err := fmt.Sscan(strings.TrimPrefix(command, "ip link set eth5 mtu "), &mtu)
			return "", err
		}
		t.Fatalf("unexpected command: %s", command)
		return "", nil
	})
	path := filepath.Join(t.TempDir(), "owned")
	s := &Interfaces{Runner: runner, OwnedPath: path}
	if err := s.loadMTUBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := s.applyInterfaceMTU(context.Background(), config.Interface{Name: "eth5", MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if mtu != 1400 || s.mtuBaseline["eth5"] != 8942 {
		t.Fatalf("after set: mtu=%d baseline=%v", mtu, s.mtuBaseline)
	}
	s = &Interfaces{Runner: runner, OwnedPath: path}
	if err := s.loadMTUBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := s.applyInterfaceMTU(context.Background(), config.Interface{Name: "eth5"}); err != nil {
		t.Fatal(err)
	}
	if mtu != 8942 || len(s.mtuBaseline) != 0 {
		t.Fatalf("after restore: mtu=%d baseline=%v", mtu, s.mtuBaseline)
	}
}

func TestForeignVirtualLinkIsRejectedBeforeMutation(t *testing.T) {
	newFakeNet(t, "qa-foreign") // A dummy has no bridge, bond, VLAN or device marker.
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	})
	s := &Interfaces{Runner: runner, owned: map[string]bool{}}
	err := s.ensure(context.Background(), config.Default(), config.Interface{ID: "bridge", Name: "qa-foreign", Type: "bridge", Enabled: true})
	if err == nil || len(commands) != 0 {
		t.Fatalf("foreign link was mutated: err=%v commands=%v", err, commands)
	}
}

func TestForeignVirtualLinkFailsPlanningBeforeNetconf(t *testing.T) {
	newFakeNet(t, "qa-foreign")
	s := NewInterfaces(netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		t.Fatal("Plan executed a system command")
		return "", nil
	}))
	s.OwnedPath = ownedFile(t)
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "bridge", Name: "qa-foreign", Type: "bridge", Enabled: true}}
	if _, err := s.Plan(config.Default(), cfg); err == nil {
		t.Fatal("foreign link was accepted by Plan")
	}
}

func TestPrepareOwnershipTracksBackendCreatedLinksAndPreservesForeignLinks(t *testing.T) {
	newFakeNet(t, "foreign")
	s := &Interfaces{OwnedPath: ownedFile(t)}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "bridge", Name: "new-bridge", Type: "bridge", Members: []string{"port"}, Enabled: true}}
	if err := s.PrepareOwnership(cfg); err != nil {
		t.Fatal(err)
	}
	newFakeNet(t, "new-bridge", "foreign")
	if _, err := s.Plan(nil, cfg); err != nil {
		t.Fatalf("backend-created link rejected: %v", err)
	}
	cfg.Interfaces[0].Name = "foreign"
	if err := s.PrepareOwnership(cfg); err == nil {
		t.Fatal("foreign link adopted")
	}
	if s.loadOwned()["foreign"] {
		t.Fatal("foreign link persisted as owned")
	}
}

func TestNetworkBroadcastReconcilesMissingAndIncorrectBroadcast(t *testing.T) {
	for _, tc := range []struct{ address, broadcast string }{
		{"192.0.2.1/24", "192.0.2.255"}, {"192.0.2.129/25", "192.0.2.255"},
		{"192.0.2.1/31", ""}, {"192.0.2.1/32", ""},
	} {
		if got := networkBroadcast(tc.address); got != tc.broadcast {
			t.Fatalf("%s: %s != %s", tc.address, got, tc.broadcast)
		}
		line := "2: eth0 inet " + tc.address
		if tc.broadcast != "" {
			if networkAddressMatches(line+" scope global", tc.address) {
				t.Fatal("missing broadcast accepted")
			}
			if networkAddressMatches(line+" brd 255.255.255.255 scope global", tc.address) {
				t.Fatal("wrong broadcast accepted")
			}
			line += " brd " + tc.broadcast
		}
		if !networkAddressMatches(line+" scope global", tc.address) {
			t.Fatal("correct address would be reapplied")
		}
	}
}
