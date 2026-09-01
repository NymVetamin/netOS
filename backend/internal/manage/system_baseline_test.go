package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type baselineRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []string
	fail    bool
}

func (r *baselineRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, strings.TrimSpace(key))
	if r.fail {
		return "", errors.New("unexpected command")
	}
	if err := r.errors[strings.TrimSpace(key)]; err != nil {
		return r.outputs[strings.TrimSpace(key)], err
	}
	return r.outputs[strings.TrimSpace(key)], nil
}

func (r *baselineRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestCaptureSystemBaselineIsCompleteAndIdempotent(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"proc/sys/net/ipv4/ip_forward":                "7\n",
		"proc/sys/net/ipv6/conf/eth0/disable_ipv6":    "1\n",
		"proc/sys/net/ipv6/conf/eth0/accept_ra":       "0\n",
		"proc/sys/net/ipv6/conf/eth0/autoconf":        "0\n",
		"proc/sys/net/ipv6/conf/default/disable_ipv6": "0\n",
		"proc/sys/net/ipv6/conf/all/disable_ipv6":     "0\n",
		"etc/systemd/timesyncd.conf.d/90-netos.conf":  "[Time]\nNTP=old.example\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := &baselineRunner{outputs: map[string]string{
		"iptables-save":  "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
		"ip6tables-save": "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
		"ip -4 route show table all proto static":        "10.0.0.0/8 via 192.0.2.1 dev eth0 proto static\n",
		"ip -6 route show table all proto static":        "blackhole 2001:db8::/32 proto static\n",
		"ip -4 route show default":                       "default via 192.0.2.1 dev eth0 proto dhcp\n",
		"ip -6 route show default":                       "default via fe80::1 dev eth0 proto ra\n",
		"ip -4 rule show":                                "0: from all lookup local\n20100: from 10.0.0.0/8 lookup custom\n32766: from all lookup main\n",
		"systemctl is-enabled tuned.service":             "disabled\n",
		"systemctl is-active tuned.service":              "inactive\n",
		"systemctl is-enabled systemd-timesyncd.service": "enabled\n",
		"systemctl is-active systemd-timesyncd.service":  "active\n",
		"systemctl is-enabled systemd-resolved.service":  "disabled\n",
		"systemctl is-active systemd-resolved.service":   "inactive\n",
		"hostnamectl --static":                           "router-before\n",
		"timedatectl show --property=Timezone --value":   "Europe/Moscow\n",
	}}
	if err := captureSystemBaseline(context.Background(), r, root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(rooted(root, systemBaselineDir), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got systemBaseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sysctl["net/ipv4/ip_forward"] != "7" || got.Sysctl["net/ipv6/conf/eth0/disable_ipv6"] != "1" {
		t.Fatalf("sysctl snapshot incomplete: %#v", got.Sysctl)
	}
	if len(got.PolicyRules4) != 1 || !strings.HasPrefix(got.PolicyRules4[0], "20100:") {
		t.Fatalf("policy snapshot = %#v", got.PolicyRules4)
	}
	if len(got.StaticRoutes4) != 1 || len(got.DefaultRoutes4) != 1 || len(got.DefaultRoutes6) != 1 || !got.IPTables6Exists || got.Tuned.Enabled != "disabled" {
		t.Fatalf("baseline incomplete: %#v", got)
	}
	if got.Hostname != "router-before" || got.Timezone != "Europe/Moscow" || !got.TimesyncdConfig.Exists || got.Timesyncd.Active != "active" || got.Resolved.Enabled != "disabled" {
		t.Fatalf("host settings baseline incomplete: %#v", got)
	}
	beforeCalls := len(r.calls)
	r.fail = true
	if err := captureSystemBaseline(context.Background(), r, root); err != nil {
		t.Fatalf("second capture must reuse original baseline: %v", err)
	}
	if len(r.calls) != beforeCalls {
		t.Fatalf("idempotent capture executed commands: %v", r.calls[beforeCalls:])
	}
}

func TestUninstallRestoresBaselineAndDeletesOnlyOwnedLinks(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	for _, name := range []string{"br-netos", "wg-ch7", "ifb-netos-3", "br-foreign", "bond-user", "d-container"} {
		if err := os.MkdirAll(filepath.Join(m.Root, "sys/class/net", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateDir, "owned-links"), []byte("br-netos\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(m.StateDir, "generated")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-qos.json"), []byte(`[{"interface":"eth9","ifb":"ifb-netos-3"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-qos-clients.json"), []byte(`["lan0"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	proc := filepath.Join(m.Root, "proc/sys/net/ipv4/ip_forward")
	if err := os.MkdirAll(filepath.Dir(proc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := systemBaseline{
		Version: 1, IPTables4: "ORIGINAL4\n", IPTables6: "ORIGINAL6\n", IPTables6Exists: true,
		StaticRoutes4:   []string{"10.0.0.0/8 via 192.0.2.1 dev eth0 proto static"},
		PolicyRules4:    []string{"20123: from 10.0.0.0/8 lookup foreign"},
		Sysctl:          map[string]string{"net/ipv4/ip_forward": "7"},
		Tuned:           serviceBaseline{Enabled: "disabled", Active: "inactive"},
		Timesyncd:       serviceBaseline{Enabled: "enabled", Active: "active"},
		Resolved:        serviceBaseline{Enabled: "disabled", Active: "inactive"},
		TimesyncdConfig: fileBaseline{Exists: true, Mode: 0o640, Data: []byte("[Time]\nNTP=old.example\n")},
		Hostname:        "router-before",
		Timezone:        "Europe/Moscow",
	}
	data, _ := json.Marshal(b)
	baselinePath := filepath.Join(m.sys(systemBaselineDir), "state.json")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		if spec.name == "tar" {
			for i, arg := range spec.args {
				if arg == "-czf" && i+1 < len(spec.args) {
					return os.WriteFile(spec.args[i+1], nil, 0o600)
				}
			}
		}
		return nil
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "ip" && contains(args, "rule") {
			return "10001: from all fwmark 1 lookup netos\n20123: from 10.0.0.0/8 lookup foreign\n", nil
		}
		return "", nil
	}
	if err := m.uninstall(context.Background(), true, false); err != nil {
		t.Fatal(err)
	}

	deleted := map[string]bool{}
	var restored4, restored6, route, rule, tunedDisabled, tunedStopped bool
	var hostname, timezone, timesyncdEnabled, timesyncdStarted, timesyncdRestarted bool
	var resolvedDisabled, resolvedStopped bool
	qosCleanup := map[string]map[string]bool{}
	for _, c := range commands {
		if c.name == "ip" && contains(c.args, "delete") && len(c.args) > 0 {
			deleted[c.args[len(c.args)-1]] = true
		}
		if c.name == "iptables-restore" && c.stdin == "ORIGINAL4\n" {
			restored4 = true
		}
		if c.name == "ip6tables-restore" && c.stdin == "ORIGINAL6\n" {
			restored6 = true
		}
		joined := c.name + " " + strings.Join(c.args, " ")
		route = route || strings.Contains(joined, "route replace 10.0.0.0/8")
		rule = rule || strings.Contains(joined, "rule add priority 20123")
		tunedDisabled = tunedDisabled || joined == "systemctl disable tuned.service"
		tunedStopped = tunedStopped || joined == "systemctl stop tuned.service"
		hostname = hostname || joined == "hostnamectl set-hostname router-before"
		timezone = timezone || joined == "timedatectl set-timezone Europe/Moscow"
		timesyncdEnabled = timesyncdEnabled || joined == "systemctl enable systemd-timesyncd.service"
		timesyncdStarted = timesyncdStarted || joined == "systemctl start systemd-timesyncd.service"
		timesyncdRestarted = timesyncdRestarted || joined == "systemctl restart systemd-timesyncd.service"
		resolvedDisabled = resolvedDisabled || joined == "systemctl disable systemd-resolved.service"
		resolvedStopped = resolvedStopped || joined == "systemctl stop systemd-resolved.service"
		if c.name == "tc" && len(c.args) == 5 && c.args[0] == "qdisc" && c.args[1] == "del" && c.args[2] == "dev" {
			if qosCleanup[c.args[3]] == nil {
				qosCleanup[c.args[3]] = map[string]bool{}
			}
			qosCleanup[c.args[3]][c.args[4]] = true
		}
	}
	if !deleted["br-netos"] || !deleted["wg-ch7"] {
		t.Fatalf("owned links were not deleted: %#v", deleted)
	}
	for _, foreign := range []string{"br-foreign", "bond-user", "d-container"} {
		if deleted[foreign] {
			t.Fatalf("foreign link deleted: %s (%#v)", foreign, deleted)
		}
	}
	for _, name := range []string{"eth9", "lan0"} {
		if !qosCleanup[name]["root"] || !qosCleanup[name]["ingress"] {
			t.Fatalf("QoS qdiscs were not removed from %s: %#v", name, qosCleanup)
		}
	}
	if qosCleanup["br-foreign"] != nil {
		t.Fatalf("foreign QoS was touched: %#v", qosCleanup)
	}
	if !restored4 || !restored6 || !route || !rule || !tunedDisabled || !tunedStopped || !hostname || !timezone || !timesyncdEnabled || !timesyncdStarted || !timesyncdRestarted || !resolvedDisabled || !resolvedStopped {
		t.Fatalf("baseline not fully restored: commands=%#v", commands)
	}
	timesyncdConfig := filepath.Join(m.Root, "etc/systemd/timesyncd.conf.d/90-netos.conf")
	if content, err := os.ReadFile(timesyncdConfig); err != nil || string(content) != "[Time]\nNTP=old.example\n" {
		t.Fatalf("timesyncd config was not restored: %q, %v", content, err)
	}
	if value, _ := os.ReadFile(proc); string(value) != "7" {
		t.Fatalf("sysctl = %q, want baseline 7", value)
	}
	if _, err := os.Stat(filepath.Dir(baselinePath)); !os.IsNotExist(err) {
		t.Fatalf("used baseline was not removed: %v", err)
	}
}

func TestCaptureSystemBaselineRejectsEveryMandatoryProbeFailure(t *testing.T) {
	commands := []string{
		"iptables-save",
		"ip -4 route show table all proto static",
		"ip -4 route show default",
		"ip -4 rule show",
		"hostnamectl --static",
		"timedatectl show --property=Timezone --value",
	}
	for _, failed := range commands {
		t.Run(failed, func(t *testing.T) {
			r := &baselineRunner{outputs: map[string]string{
				"iptables-save": "*filter\nCOMMIT\n",
			}, errors: map[string]error{failed: errors.New("injected")}}
			if err := captureSystemBaseline(context.Background(), r, t.TempDir()); err == nil {
				t.Fatalf("failure of %s was accepted", failed)
			}
		})
	}
	// IPv6 tables and route support are optional on kernels built without IPv6.
	r := &baselineRunner{outputs: map[string]string{
		"iptables-save":        "*filter\nCOMMIT\n",
		"hostnamectl --static": "router\n",
		"timedatectl show --property=Timezone --value": "UTC\n",
	}, errors: map[string]error{
		"ip6tables-save": errors.New("unsupported"),
		"ip -6 route show table all proto static": errors.New("unsupported"),
	}}
	if err := captureSystemBaseline(context.Background(), r, t.TempDir()); err != nil {
		t.Fatalf("optional IPv6 failure rejected: %v", err)
	}
}

func TestReadSystemBaselineRejectsMalformedAndIncompleteState(t *testing.T) {
	for name, content := range map[string]string{"malformed": "{", "incomplete": `{"version":1,"sysctl":{}}`} {
		t.Run(name, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			path := filepath.Join(m.sys(systemBaselineDir), "state.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.readSystemBaseline(); err == nil {
				t.Fatalf("%s baseline accepted", name)
			}
		})
	}
}

func TestRestoreServiceBaselineEverySystemdState(t *testing.T) {
	tests := []struct {
		name  string
		state serviceBaseline
		want  []string
	}{
		{"enabled active", serviceBaseline{"enabled", "active"}, []string{"systemctl enable unit.service", "systemctl start unit.service"}},
		{"runtime activating", serviceBaseline{"enabled-runtime", "activating"}, []string{"systemctl enable --runtime unit.service", "systemctl start unit.service"}},
		{"disabled inactive", serviceBaseline{"disabled", "inactive"}, []string{"systemctl disable unit.service", "systemctl stop unit.service"}},
		{"masked failed", serviceBaseline{"masked", "failed"}, []string{"systemctl mask unit.service", "systemctl stop unit.service"}},
		{"runtime mask deactivating", serviceBaseline{"masked-runtime", "deactivating"}, []string{"systemctl mask --runtime unit.service", "systemctl stop unit.service"}},
		{"static unknown", serviceBaseline{"static", "unknown"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := testManager()
			var got []string
			m.Run = func(_ context.Context, c command) error {
				got = append(got, c.name+" "+strings.Join(c.args, " "))
				return nil
			}
			if err := m.restoreServiceBaseline(context.Background(), "unit.service", tt.state); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("commands=%v want=%v", got, tt.want)
			}
		})
	}
	m, _ := testManager()
	m.Run = func(context.Context, command) error { return errors.New("injected") }
	if err := m.restoreServiceBaseline(context.Background(), "unit.service", serviceBaseline{"enabled", "active"}); err == nil {
		t.Fatal("systemctl failure was ignored")
	}
}

func TestRestoreBaselineFirewallPropagatesBothFamilyFailures(t *testing.T) {
	for _, failed := range []string{"iptables-restore", "ip6tables-restore"} {
		t.Run(failed, func(t *testing.T) {
			m, _ := testManager()
			m.Run = func(_ context.Context, c command) error {
				if c.name == failed {
					return errors.New("injected")
				}
				return nil
			}
			b := &systemBaseline{IPTables4: "v4", IPTables6: "v6", IPTables6Exists: true}
			if err := m.restoreBaselineFirewall(context.Background(), b); err == nil {
				t.Fatalf("%s failure ignored", failed)
			}
		})
	}
}

func TestRestoreBaselineHostSettingsHandlesAbsentAndDefaultMode(t *testing.T) {
	t.Run("remove netOS file when originally absent", func(t *testing.T) {
		m, _ := testManager()
		sandbox(t, m)
		path := m.sys("/etc/systemd/timesyncd.conf.d/90-netos.conf")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("netos"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := m.restoreBaselineHostSettings(context.Background(), &systemBaseline{}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("netOS timesyncd file remains: %v", err)
		}
	})
	t.Run("zero stored mode uses safe default", func(t *testing.T) {
		m, _ := testManager()
		sandbox(t, m)
		b := &systemBaseline{TimesyncdConfig: fileBaseline{Exists: true, Data: []byte("old")}}
		if err := m.restoreBaselineHostSettings(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(m.sys("/etc/systemd/timesyncd.conf.d/90-netos.conf"))
		if err != nil || string(data) != "old" {
			t.Fatalf("content=%q err=%v", data, err)
		}
	})
}

func TestUninstallKeepDataRequestsFreshFutureBaseline(t *testing.T) {
	t.Run("replace existing baseline with marker", func(t *testing.T) {
		m, _ := testManager()
		sandbox(t, m)
		b := systemBaseline{Version: 1, IPTables4: "*filter\nCOMMIT\n", Sysctl: map[string]string{}}
		data, _ := json.Marshal(b)
		path := filepath.Join(m.sys(systemBaselineDir), "state.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := m.uninstall(context.Background(), true, true); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("used baseline remains after uninstall: %v", err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".capture-required")); err != nil {
			t.Fatalf("fresh capture marker missing: %v", err)
		}
	})
	t.Run("legacy install requests capture on reinstall", func(t *testing.T) {
		m, _ := testManager()
		sandbox(t, m)
		if err := m.uninstall(context.Background(), true, true); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(m.sys(systemBaselineDir), ".capture-required")
		if info, err := os.Stat(marker); err != nil || info.Size() != 0 {
			t.Fatalf("capture marker missing: %v, %v", info, err)
		}
	})
}
