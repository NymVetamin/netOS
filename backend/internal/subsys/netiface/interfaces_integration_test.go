//go:build linux

package netiface

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationInterfacesFullLifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is not installed")
	}
	const ownedPath = "/run/netos-qa-interfaces-owned"
	physical := [][2]string{{"qap1", "qap1peer"}, {"qap2", "qap2peer"}, {"qab1", "qab1peer"}, {"qab2", "qab2peer"}}
	virtual := []string{"qabr0", "qav100", "qabond0", "qae0"}
	carriers := []string{dummyNameFor("qae0"), carrierPeerNameFor("qae0"), dummyNameFor("qabr0"), carrierPeerNameFor("qabr0")}
	for _, name := range append(append([]string{}, virtual...), carriers...) {
		if linkExists(name) {
			t.Fatalf("refusing to reuse existing integration link %s", name)
		}
	}
	for _, pair := range physical {
		if linkExists(pair[0]) || linkExists(pair[1]) {
			t.Fatalf("refusing to reuse existing integration veth %s/%s", pair[0], pair[1])
		}
	}
	cleanup := func() {
		for _, name := range append(append([]string{}, virtual...), carriers...) {
			_ = exec.Command("ip", "link", "delete", name).Run()
		}
		for _, pair := range physical {
			_ = exec.Command("ip", "link", "delete", pair[0]).Run()
			_ = exec.Command("ip", "link", "delete", pair[1]).Run()
		}
		_ = os.Remove(ownedPath)
	}
	cleanup()
	t.Cleanup(cleanup)
	// An existing empty file disables the one-time legacy-name migration. The
	// integration test must never classify unrelated host links by prefix.
	if err := os.WriteFile(ownedPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	runner := system.NewExec()
	for _, pair := range physical {
		mustRunVPNStyle(t, runner, "ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		mustRunVPNStyle(t, runner, "ip", "link", "set", pair[0], "up")
		mustRunVPNStyle(t, runner, "ip", "link", "set", pair[1], "up")
	}

	s := NewInterfaces(runner)
	s.OwnedPath = ownedPath
	cfg := interfaceLifecycleConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	assertSysfsValue(t, "/sys/class/net/qabr0/bridge/stp_state", "1")
	assertSysfsValue(t, "/sys/class/net/qae0/carrier", "1")

	stableNames := []string{"qabr0", "qav100", "qabond0", "qae0", dummyNameFor("qae0"), carrierPeerNameFor("qae0")}
	before := linkIndexes(t, stableNames)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if after := linkIndexes(t, stableNames); !sameIndexes(before, after) {
		t.Fatalf("idempotent Apply recreated links: before=%v after=%v", before, after)
	}

	// A bridge with no real member gains a carrier pair and releases the old
	// port. Restoring the member removes the pair and enslaves the port again.
	cfg.Interfaces[4].Members = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if masterOf("qap1") != "" || !linkExists(dummyNameFor("qabr0")) {
		t.Fatalf("member-to-empty transition is incomplete: master=%q carrier=%v", masterOf("qap1"), linkExists(dummyNameFor("qabr0")))
	}
	cfg.Interfaces[4].Members = []string{"p1"}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if linkExists(dummyNameFor("qabr0")) || masterOf("qap1") != "qabr0" {
		t.Fatalf("empty-to-member transition is incomplete")
	}

	oldVLANIndex := linkIndex(t, "qav100")
	cfg.Interfaces[5].VLANID = 101
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := linkIndex(t, "qav100"); got == oldVLANIndex {
		t.Fatalf("VLAN ID change did not recreate the immutable kernel link: ifindex=%d", got)
	}

	physicalOnly := config.Default()
	physicalOnly.Interfaces = append([]config.Interface(nil), cfg.Interfaces[:4]...)
	if err := s.Apply(context.Background(), physicalOnly); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), physicalOnly); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(virtual, carriers...) {
		if linkExists(name) {
			t.Fatalf("owned virtual link remains after deletion: %s", name)
		}
	}
	for _, pair := range physical {
		if !linkExists(pair[0]) || !linkExists(pair[1]) {
			t.Fatalf("physical veth was deleted: %s/%s", pair[0], pair[1])
		}
	}
	if data, err := os.ReadFile(ownedPath); err != nil || strings.TrimSpace(string(data)) != "" {
		t.Fatalf("owned link file is not empty after cleanup: %q (%v)", data, err)
	}
}

func interfaceLifecycleConfig() *config.Config {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "p1", Name: "qap1", Type: "physical", Enabled: true, MTU: 1450, MAC: "02:00:00:00:00:11"},
		{ID: "p2", Name: "qap2", Type: "physical", Enabled: true},
		{ID: "b1", Name: "qab1", Type: "physical", Enabled: true},
		{ID: "b2", Name: "qab2", Type: "physical", Enabled: true},
		{ID: "bridge", Name: "qabr0", Type: "bridge", Enabled: true, Members: []string{"p1"}},
		{ID: "vlan", Name: "qav100", Type: "vlan", Enabled: true, Parent: "p2", VLANID: 100},
		{ID: "bond", Name: "qabond0", Type: "bond", Enabled: true, Members: []string{"b1", "b2"}},
		{ID: "empty", Name: "qae0", Type: "bridge", Enabled: true},
	}
	return cfg
}

func linkIndexes(t *testing.T, names []string) map[string]int {
	t.Helper()
	result := map[string]int{}
	for _, name := range names {
		result[name] = linkIndex(t, name)
	}
	return result
}

func linkIndex(t *testing.T, name string) int {
	t.Helper()
	data, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sameIndexes(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func assertSysfsValue(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
