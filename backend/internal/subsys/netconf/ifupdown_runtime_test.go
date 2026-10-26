package netconf

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

type hotplugRunner struct {
	*backendUnitRunner
	fail, sticky bool
	stops        int
}

func (r *hotplugRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	if strings.HasPrefix(cmd, "systemctl list-units ") {
		var out string
		for unit, active := range r.active {
			if active && strings.HasPrefix(unit, "ifup@") {
				out += unit + " loaded active exited ifup\n"
			}
		}
		return out, nil
	}
	if cmd == "systemctl stop ifup@eth0.service" || cmd == "ifdown eth0" {
		r.stops++
		data, _ := os.ReadFile(ifupdownMain)
		if !strings.Contains(string(data), "iface eth0 inet dhcp") {
			return "", fmt.Errorf("original stanza removed before ifdown")
		}
		if r.fail {
			return "", fmt.Errorf("injected stop failure")
		}
		if !r.sticky {
			r.active["ifup@eth0.service"] = false
			_ = os.WriteFile(ifupdownStatePath, []byte("spare=spare\n"), 0600)
		}
		return "", nil
	}
	return r.backendUnitRunner.Run(ctx, name, args...)
}

func TestHotplugOwnershipReleaseRetryAndRestore(t *testing.T) {
	for _, backend := range []string{"netos", "networkd", "ifupdown"} {
		t.Run(backend, func(t *testing.T) {
			useTemporaryPaths(t)
			original := "auto lo\niface lo inet loopback\nallow-hotplug eth0 spare\niface eth0 inet dhcp\niface spare inet dhcp\n"
			if err := os.MkdirAll(ifupdownDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ifupdownMain, []byte(original), 0640); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(ifupdownStatePath, []byte("eth0=eth0\nspare=spare\n"), 0600)
			r := &hotplugRunner{backendUnitRunner: newBackendUnitRunner(), fail: true}
			r.active["ifup@eth0.service"] = true
			r.active["ifup@spare.service"] = true
			cfg := routerConfig()
			cfg.System.NetworkBackend = backend
			s := New(r, nil)
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatal("competing hotplug accepted")
			}
			if err := s.Apply(context.Background(), cfg); err == nil {
				t.Fatal("stop failure ignored")
			}
			got, _ := os.ReadFile(ifupdownMain)
			if string(got) != original {
				t.Fatal("failed release changed original")
			}
			r.fail = false
			r.sticky = true
			if err := s.Apply(context.Background(), cfg); err == nil {
				t.Fatal("surviving owner accepted")
			}
			r.sticky = false
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if !r.active["ifup@spare.service"] {
				t.Fatal("unmanaged owner stopped")
			}
			got, _ = os.ReadFile(ifupdownMain)
			if strings.Contains(string(got), "eth0") || !strings.Contains(string(got), "allow-hotplug spare") {
				t.Fatalf("bad input: %s", got)
			}
			before := r.stops
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if r.stops != before {
				t.Fatal("clean repeat stops links")
			}
			if err := RestoreIfupdown(""); err != nil {
				t.Fatal(err)
			}
			got, _ = os.ReadFile(ifupdownMain)
			if string(got) != original {
				t.Fatal("restore differs")
			}
			info, _ := os.Stat(ifupdownMain)
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0640 {
				t.Fatal("mode lost")
			}
		})
	}
}

func TestIfupdownPreflightBeforeRuntimeRelease(t *testing.T) {
	useTemporaryPaths(t)
	_ = os.MkdirAll(ifupdownDir, 0755)
	_ = os.WriteFile(ifupdownMain, []byte("mapping eth*\n script unknown\n"), 0644)
	called := false
	_, err := takeOverIfupdownAfter([]string{"eth0"}, false, func() error { called = true; return nil })
	if err == nil || called {
		t.Fatal("unsafe mapping reached runtime release")
	}
}

func TestIfupUnitEscaping(t *testing.T) {
	for name, want := range map[string]string{"eth0": "ifup@eth0.service", "wan-1": "ifup@wan\\x2d1.service", ".wan": "ifup@\\x2ewan.service", "eth0.1": "ifup@eth0.1.service"} {
		if got := ifupUnit(name); got != want {
			t.Fatalf("%s: %s != %s", name, got, want)
		}
	}
}
