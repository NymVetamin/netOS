package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dashboardFixture(t *testing.T, root, name, data string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardResourcesCountersAndRecovery(t *testing.T) {
	proc, sys := t.TempDir(), t.TempDir()
	dashboardFixture(t, proc, "stat", "cpu 100 0 100 800 0 0 0 0 70 0\n")
	dashboardFixture(t, proc, "meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\n")
	m := &dashboardMetrics{}
	r := m.read(proc, sys)
	if r.CPU != nil || r.Temperature != nil || *r.MemoryTotal != 1024000 || *r.MemoryUsed != 409600 {
		t.Fatalf("initial: %+v", r)
	}
	dashboardFixture(t, proc, "stat", "cpu 110 0 110 880 0 0 0 0 80 0\n")
	m.at = time.Now().Add(-2 * time.Second)
	r = m.read(proc, sys)
	if r.CPU == nil || *r.CPU != 20 {
		t.Fatalf("expected 20%%, got %+v", r.CPU)
	}
	dashboardFixture(t, proc, "stat", "broken")
	if m.read(proc, sys).CPU != nil {
		t.Fatal("failed read must not retain stale CPU")
	}
	dashboardFixture(t, proc, "stat", "cpu 1 0 1 8 0 0 0 0\n")
	if m.read(proc, sys).CPU != nil {
		t.Fatal("recovery requires a new baseline")
	}
	for _, raw := range []string{"", "MemTotal: 100 kB", "MemTotal: 100 kB\nMemAvailable: 200 kB", "MemTotal: bad kB\nMemAvailable: 0 kB"} {
		if total, used := memoryUsage(raw); total != nil || used != nil {
			t.Fatalf("accepted invalid memory: %q", raw)
		}
	}
}

func TestDashboardTemperatureUsesCPUOnly(t *testing.T) {
	root := t.TempDir()
	dashboardFixture(t, root, "class/hwmon/hwmon0/name", "nvme")
	dashboardFixture(t, root, "class/hwmon/hwmon0/temp1_input", "99000")
	dashboardFixture(t, root, "class/hwmon/hwmon1/name", "coretemp")
	dashboardFixture(t, root, "class/hwmon/hwmon1/temp1_input", "49000")
	dashboardFixture(t, root, "class/hwmon/hwmon1/temp2_input", "51000")
	dashboardFixture(t, root, "class/hwmon/hwmon1/temp3_input", "999000")
	if v := cpuTemperature(root); v == nil || *v != 51 {
		t.Fatalf("CPU temp: %v", v)
	}
	root = t.TempDir()
	dashboardFixture(t, root, "class/thermal/thermal_zone0/type", "acpitz")
	dashboardFixture(t, root, "class/thermal/thermal_zone0/temp", "85000")
	if cpuTemperature(root) != nil {
		t.Fatal("ACPI zone is not necessarily CPU")
	}
	dashboardFixture(t, root, "class/thermal/thermal_zone1/type", "x86_pkg_temp")
	dashboardFixture(t, root, "class/thermal/thermal_zone1/temp", "42000")
	if v := cpuTemperature(root); v == nil || *v != 42 {
		t.Fatalf("thermal fallback: %v", v)
	}
}

type dashboardRunner struct {
	calls int
	fail  bool
}

func (r *dashboardRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls++
	if name != "systemctl" || !strings.Contains(strings.Join(args, " "), "list-units --all") {
		return "", fmt.Errorf("unexpected command")
	}
	if r.fail {
		return "", fmt.Errorf("unavailable")
	}
	return "netos-unbound.service loaded active running netOS Unbound\nnetos-samba.service loaded failed failed netOS Samba\nnetos-maintenance.service loaded inactive dead netOS Maintenance\nssh.service loaded active running SSH\n", nil
}
func (r *dashboardRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestDashboardServicesCachedAndRecover(t *testing.T) {
	s := observationServer(t, &observationRunner{})
	runner := &dashboardRunner{}
	s.Collector.Runner = runner
	rows, ok := s.dashboardServiceStatus(context.Background())
	if !ok || len(rows) != 3 || rows[1].State != "failed" || rows[0].Title != "Unbound" {
		t.Fatalf("rows=%+v ok=%v", rows, ok)
	}
	s.dashboardServiceStatus(context.Background())
	if runner.calls != 1 {
		t.Fatal("no cache")
	}
	runner.fail = true
	s.dashboardServices.at = time.Now().Add(-6 * time.Second)
	if rows, ok = s.dashboardServiceStatus(context.Background()); ok || len(rows) != 0 {
		t.Fatal("failure presented as healthy/stale")
	}
	runner.fail = false
	s.dashboardServices.at = time.Now().Add(-6 * time.Second)
	if _, ok = s.dashboardServiceStatus(context.Background()); !ok {
		t.Fatal("did not recover")
	}
}

func TestDashboardOverviewIsOptInAndPermissionScoped(t *testing.T) {
	s := observationServer(t, &observationRunner{})
	for _, tt := range []struct {
		query, role string
		want        bool
	}{{"", "admin", false}, {"?overview=1", "", false}, {"?overview=1", "admin", true}} {
		r := httptest.NewRequest("GET", "/api/status"+tt.query, nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxRole, tt.role))
		w := httptest.NewRecorder()
		s.handleStatus(w, r)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		for _, key := range []string{"resources", "client_summary", "services_available"} {
			if strings.Contains(w.Body.String(), `"`+key+`"`) != tt.want {
				t.Fatalf("%+v leaked/missing %s", tt, key)
			}
		}
	}
}
