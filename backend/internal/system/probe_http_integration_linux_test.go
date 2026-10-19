//go:build linux

package system_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/multiwan"
	"github.com/netos-router/netos/internal/system"
)

func TestHTTPProbeControllersUseNativeAndFallbackTargets(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	t.Setenv("HOME", t.TempDir())
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	runner := system.NewExec()
	runner.OnCommand = func(name string, _ []string) { t.Fatalf("unexpected subprocess %s", name) }
	channel := channels.New(runner, t.TempDir())
	wan := multiwan.New(runner, t.TempDir(), nil)
	for _, targets := range [][]string{{s.URL + "/bad"}, {s.URL + "/bad", s.URL + "/good"}, {s.URL + "/good"}} {
		want := targets[len(targets)-1] == s.URL+"/good"
		probe := config.Probe{Type: "http", Targets: targets, Timeout: 1}
		if got := channel.Probe(context.Background(), config.Channel{Type: "xray", Probe: probe}, ""); got != want {
			t.Fatalf("channel healthy=%v want=%v", got, want)
		}
		if got := wan.Probe(context.Background(), config.WAN{Probe: probe}, ""); got != want {
			t.Fatalf("WAN healthy=%v want=%v", got, want)
		}
	}
}
