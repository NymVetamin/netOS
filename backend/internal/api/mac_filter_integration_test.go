//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationMACFilterValidation(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	host, hostErr := os.Readlink("/proc/1/ns/net")
	if err != nil || hostErr != nil || self == host {
		t.Fatal("isolated network namespace required")
	}
	parse := func(mac string) error {
		cmd := exec.Command("iptables-restore", "--test")
		cmd.Stdin = strings.NewReader("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -m mac --mac-source " + mac + " -j DROP\nCOMMIT\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	const valid = "02:00:00:00:00:01"
	if err := parse(valid); err != nil {
		t.Fatalf("six-byte parser: %v", err)
	}
	for _, alternative := range []string{"02-00-00-00-00-01", "0200.0000.0001"} {
		t.Logf("alternative six-byte syntax %s parser result: %v", alternative, parse(alternative))
	}
	for _, mac := range []string{"02:00:00:00:00:00:00:01", strings.Repeat("00:", 19) + "01"} {
		t.Run(mac, func(t *testing.T) {
			if err := parse(mac); err == nil {
				t.Fatal("oversized MAC accepted by iptables")
			}
			s, cookie, csrf, _ := transactionServer(t)
			fw := firewall.New(system.NewExec(), t.TempDir())
			if err := s.Engine.Register(fw); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if pending, _ := s.Engine.Pending(); pending {
					_, _ = s.Engine.Confirm(s.Store.MarkActive)
				}
			})
			h := s.Routes()
			request := func(method, path string, payload any, match string) *httptest.ResponseRecorder {
				t.Helper()
				body, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r.AddCookie(cookie)
				r.Header.Set(csrfHeader, csrf)
				if match != "" {
					r.Header.Set("If-Match", match)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			cfg := *s.Engine.Current()
			cfg.Firewall.Rules = append(cfg.Firewall.Rules, config.FirewallRule{ID: "mac-test", Enabled: true, Zone: "global", Flow: "in", Action: "drop", SrcMAC: mac})
			cfg.Policies = []config.Policy{{ID: "mac-policy", Enabled: true, Channel: config.InternetBlockChannel, SrcMAC: mac}}
			index := len(cfg.Firewall.Rules) - 1
			for repeat := 0; repeat < 2; repeat++ {
				w := request(http.MethodPost, "/api/config/validate", &cfg, "")
				var result config.ValidationResult
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.HasErrors() {
					t.Fatalf("invalid validation: %d %s", w.Code, w.Body.String())
				}
				for _, field := range []string{fmt.Sprintf("firewall.rules[%d].src_mac", index), "policies[0].src_mac"} {
					if !strings.Contains(w.Body.String(), field) {
						t.Fatalf("missing error field %s", field)
					}
				}
				if w := request(http.MethodPut, "/api/config", &cfg, "1"); w.Code != 422 {
					t.Fatalf("invalid save: %d %s", w.Code, w.Body.String())
				}
			}
			cfg.Firewall.Rules[index].SrcMAC = valid
			cfg.Policies[0].SrcMAC = valid
			checked := request(http.MethodPost, "/api/config/validate", &cfg, "")
			var validation config.ValidationResult
			if checked.Code != 200 || json.Unmarshal(checked.Body.Bytes(), &validation) != nil || validation.HasErrors() {
				t.Fatalf("corrected validation: %d %s", checked.Code, checked.Body.String())
			}
			w := request(http.MethodPut, "/api/config", &cfg, "1")
			var saved configResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil {
				t.Fatalf("corrected save: %d %s", w.Code, w.Body.String())
			}
			w = request(http.MethodPost, "/api/config/apply", applyRequest{DraftVersion: saved.DraftVersion}, "")
			if w.Code != 200 {
				t.Fatalf("apply: %d %s", w.Code, w.Body.String())
			}
			if revision, deadline := s.Engine.PendingRevision(); !deadline.IsZero() {
				if w := request(http.MethodPost, "/api/config/confirm", nil, strconv.FormatInt(revision, 10)); w.Code != 200 {
					t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
				}
			}
			for range 2 {
				if err := fw.Apply(context.Background(), s.Engine.Current()); err != nil {
					t.Fatal(err)
				}
				if err := fw.Health(context.Background(), s.Engine.Current()); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("oversized MAC rejected by native parser/API; corrected rule applied and repeated on Linux")
		})
	}
}
