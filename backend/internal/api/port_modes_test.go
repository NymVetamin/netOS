package api

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/runtime"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type portModeRunner struct{ calls []string }

func (r *portModeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return "Supported link modes: 100baseT/Full 1000baseT/Full\nSupports auto-negotiation: Yes\nAdvertised link modes: 1000baseT/Full\nAuto-negotiation: on", nil
}
func (r *portModeRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", fmt.Errorf("unexpected mutation")
}
func TestPortModesPhysicalReadOnly(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"eth0", "br-lan"} {
		base := filepath.Join(root, name)
		if err := os.MkdirAll(base, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "ifindex"), []byte("2"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "eth0", "device"), 0755); err != nil {
		t.Fatal(err)
	}
	run := &portModeRunner{}
	c := runtime.NewCollector(run, "")
	c.SysClassNet = root
	s := &Server{Collector: c, StorageRunner: run}
	for _, name := range []string{"br-lan", "missing", "eth0"} {
		req := httptest.NewRequest("GET", "/api/interfaces/"+name+"/modes", nil)
		req.SetPathValue("name", name)
		w := httptest.NewRecorder()
		s.handlePortModes(w, req)
		if name == "eth0" {
			if w.Code != 200 || !strings.Contains(w.Body.String(), "1000baseT/Full") {
				t.Fatal(w.Code, w.Body.String())
			}
		} else if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if strings.Join(run.calls, ",") != "ethtool eth0" {
		t.Fatal(run.calls)
	}
}
