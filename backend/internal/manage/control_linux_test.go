package manage

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIApplyPinsSelectedOwner(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic", true: "explicit"}[explicit], func(t *testing.T) {
			m, out := testManager()
			// Unix socket paths have a short platform limit.
			root, err := os.MkdirTemp("", "netos-ctl-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			m.Root = root
			socket := filepath.Join(root, "run/netosd/control.sock")
			if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			const owner = "alice+qa"
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/draft":
					want := ""
					if explicit {
						want = owner
					}
					if r.Method != "GET" || r.URL.Query().Get("user") != want {
						t.Error("wrong draft selection", r.URL)
					}
					_, _ = w.Write([]byte(`{"owner":"alice+qa","dirty":true,"draft_version":73}`))
				case "/apply":
					var body struct {
						Version uint64 `json:"draft_version"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if r.Method != "POST" || r.URL.Query().Get("user") != owner || body.Version != 73 {
						t.Error("owner or version not pinned", r.URL, body)
					}
					_, _ = w.Write([]byte(`{"revision":42,"needs_confirm":true}`))
				case "/confirm":
					_, _ = w.Write([]byte(`{"ok":true}`))
				default:
					t.Error("unexpected path", r.URL.Path)
					http.NotFound(w, r)
				}
			})}
			go server.Serve(ln)
			t.Cleanup(func() { _ = server.Close() })
			args := []string{"apply"}
			if explicit {
				args = append(args, "--user", owner)
			}
			if err := m.Execute(context.Background(), args); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "42") || !strings.Contains(out.String(), "netos confirm") {
				t.Fatal(out.String())
			}
			if err := m.Execute(context.Background(), []string{"confirm"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
