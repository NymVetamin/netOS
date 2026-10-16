package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLiveFirewallParser(t *testing.T) {
	raw := "*filter\n:INPUT DROP [3:99]\n:WAN-IN - [0:0]\n:EMPTY - [0:0]\n[1:60] -A INPUT -i eth0 -j WAN-IN\n[2:80] -A WAN-IN -m comment --comment \"VPN server\" -j ACCEPT\n-A WAN-IN -j DROP\nCOMMIT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -j MASQUERADE\nCOMMIT\n"
	tables := parseLiveFirewall(raw)
	if len(tables) != 2 || len(tables[0].Chains) != 3 || len(tables[0].Chains[1].Rules) != 2 || len(tables[0].Chains[2].Rules) != 0 {
		t.Fatalf("%+v", tables)
	}
	if tables[0].Chains[0].Policy != "DROP" || tables[0].Chains[1].Rules[1] != "-A WAN-IN -j DROP" {
		t.Fatal("order/policy lost")
	}
	if liveRuleComment(tables[0].Chains[1].Rules[0]) != "VPN server" {
		t.Fatal("comment lost")
	}
}

type liveFirewallRunner struct{ commands []string }

func (r *liveFirewallRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	if name == "ip6tables-save" {
		return "", fmt.Errorf("fixture failure")
	}
	return "*filter\n:INPUT DROP [0:0]\n-A INPUT -j DROP\nCOMMIT\n", nil
}
func TestLiveFirewallReadOnlyAndPartialFailure(t *testing.T) {
	runner := &liveFirewallRunner{}
	s := &Server{StorageRunner: runner}
	w := httptest.NewRecorder()
	s.handleLiveFirewall(w, httptest.NewRequest("GET", "/api/firewall/live", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture failure") || !strings.Contains(w.Body.String(), "-A INPUT -j DROP") {
		t.Fatal(w.Body.String())
	}
	if strings.Join(runner.commands, ",") != "iptables-save -c,ip6tables-save -c" {
		t.Fatal(runner.commands)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cached live state")
	}
}

func (r *liveFirewallRunner) RunInput(_ context.Context, _ string, _ string, _ ...string) (string, error) {
	return "", fmt.Errorf("unexpected write command")
}

func TestLiveFirewallCapturedSnapshot(t *testing.T) {
	path := os.Getenv("NETOS_FIREWALL_SNAPSHOT")
	if path == "" {
		t.Skip("optional read-only OS capture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tables := parseLiveFirewall(string(raw))
	count := 0
	for _, table := range tables {
		for _, chain := range table.Chains {
			count += len(chain.Rules)
		}
	}
	expected := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "-A ") {
			expected++
		}
	}
	if expected == 0 || count != expected {
		t.Fatalf("parsed %d of %d OS rules", count, expected)
	}
	t.Logf("preserved %d rules across %d tables", count, len(tables))
}

func TestFirewallPreviewDoesNotExecuteOrSave(t *testing.T) {
	runner := &liveFirewallRunner{}
	s := &Server{StorageRunner: runner}
	w := httptest.NewRecorder()
	s.handleFirewallPreview(w, httptest.NewRequest("POST", "/api/firewall/preview", strings.NewReader(`{"firewall":{"enabled":true,"rules":[{"id":"qa","name":"test","enabled":true,"zone":"global","flow":"in","action":"accept"}]}}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rule_ids"`) || !strings.Contains(w.Body.String(), `"qa"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(runner.commands) != 0 {
		t.Fatal(runner.commands)
	}
	w = httptest.NewRecorder()
	s.handleFirewallPreview(w, httptest.NewRequest("POST", "/api/firewall/preview", strings.NewReader("invalid")))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
