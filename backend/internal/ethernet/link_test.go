package ethernet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const sample = `Settings for eth0:
 Supported link modes: 10baseT/Half 10baseT/Full
                       100baseT/Full 1000baseT/Full
 Supports auto-negotiation: Yes
 Advertised link modes: 100baseT/Full 1000baseT/Full
 Advertised auto-negotiation: Yes
 Speed: 1000Mb/s
 Duplex: Full
 Auto-negotiation: on
`

func TestParse(t *testing.T) {
	s := Parse(sample)
	if len(s.Supported) != 4 || len(s.Advertised) != 2 || !s.Autoneg || !s.CanAutoneg || s.Speed != 1000 || s.Duplex != "full" {
		t.Fatalf("%+v", s)
	}
}

func TestSetAdvertisesInDriverOrder(t *testing.T) {
	current := Settings{Supported: []string{"1000baseX/Full", "100baseT/Half", "1000baseT/Full", "1000baseX/Full"}}
	want := Settings{Autoneg: true, Advertised: []string{"1000baseT/Full", "1000baseX/Full", "1000baseT/Full", "unsupported"}}
	expected := []string{"-s", "eth0", "autoneg", "on", "advertise", "1000baseX/Full", "on", "100baseT/Half", "off", "1000baseT/Full", "on", "1000baseX/Full", "on"}
	failure := errors.New("set rejected")
	run := func(_ context.Context, cmd string, args ...string) (string, error) {
		if cmd != "ethtool" || !slices.Equal(args, expected) {
			t.Fatalf("unexpected command %s %q", cmd, args)
		}
		return "", failure
	}
	if err := set(context.Background(), run, "eth0", current, want); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

// Emulate a driver, retaining only the requested advertised modes. Checks that
// the durable original settings exist BEFORE the first write to the driver.
func driver(t *testing.T, path string, cur *Settings, writes *int, fail *bool) Run {
	return func(_ context.Context, cmd string, args ...string) (string, error) {
		t.Helper()
		if cmd != "ethtool" {
			t.Fatalf("command %s", cmd)
		}
		if len(args) > 1 {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("baseline missing before mutation", err)
			}
			var journal map[string]Settings
			if err := json.Unmarshal(data, &journal); err != nil {
				t.Fatal(err)
			}
			original, ok := journal[args[1]]
			if !ok || (*writes == 0 && !same(original, *cur)) {
				t.Fatal("missing original mode before driver change")
			}
			*writes++
			if *fail {
				return "", errors.New("driver failure")
			}
			if len(args) < 4 || args[0] != "-s" || args[1] != "eth0" {
				t.Fatalf("args %v", args)
			}
			cur.Autoneg = args[3] == "on"
			if cur.Autoneg {
				if args[4] != "advertise" {
					t.Fatalf("args %v", args)
				}
				cur.Advertised = nil
				for i := 5; i < len(args); i += 2 {
					if args[i+1] == "on" {
						cur.Advertised = append(cur.Advertised, args[i])
					}
				}
			} else {
				fmt.Sscanf(args[5], "%d", &cur.Speed)
				cur.Duplex = args[7]
			}
			return "", nil
		}
		return fmt.Sprintf("Supported link modes: %s\nSupports auto-negotiation: Yes\nAdvertised link modes: %s\nAuto-negotiation: %s\nSpeed: %dMb/s\nDuplex: %s\n", strings.Join(cur.Supported, " "), strings.Join(cur.Advertised, " "), map[bool]string{true: "on", false: "off"}[cur.Autoneg], cur.Speed, cur.Duplex), nil
	}
}
func TestApplyRepeatChangeAndRestoreOriginal(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(fmt.Sprint(forced), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original.json")
			cur := Parse(sample)
			cur.Autoneg = !forced
			original := cur
			writes := 0
			fail := false
			run := driver(t, path, &cur, &writes, &fail)
			ctx := context.Background()
			if err := Apply(ctx, run, path, map[string]string{"eth0": "100baseT/Full"}); err != nil {
				t.Fatal(err)
			}
			if !cur.Autoneg || strings.Join(cur.Advertised, ",") != "100baseT/Full" {
				t.Fatal(cur)
			}
			if err := Apply(ctx, run, path, map[string]string{"eth0": "100baseT/Full"}); err != nil {
				t.Fatal(err)
			}
			if writes != 1 {
				t.Fatal("repeated apply restarted negotiation", writes)
			}
			if err := Apply(ctx, run, path, map[string]string{"eth0": "auto"}); err != nil {
				t.Fatal(err)
			}
			if len(cur.Advertised) != 4 {
				t.Fatal(cur)
			}
			// A fresh Apply invocation restores from disk, as after restart or uninstall.
			if err := Apply(ctx, run, path, nil); err != nil {
				t.Fatal(err)
			}
			if !same(cur, original) {
				t.Fatalf("got %+v original %+v", cur, original)
			}
			raw, _ := os.ReadFile(path)
			if string(raw) != "{}" {
				t.Fatal(string(raw))
			}
		})
	}
}
func TestRejectUnsupportedAndRetainBaselineOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original.json")
	cur := Parse(sample)
	writes := 0
	fail := false
	run := driver(t, path, &cur, &writes, &fail)
	ctx := context.Background()
	if err := Apply(ctx, run, path, map[string]string{"eth0": "2500baseT/Full"}); err == nil {
		t.Fatal("unsupported accepted")
	}
	if writes != 0 {
		t.Fatal("mutated unsupported mode")
	}
	fail = true
	if err := Apply(ctx, run, path, map[string]string{"eth0": "100baseT/Full"}); err == nil {
		t.Fatal("ignored driver error")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("lost recovery baseline")
	}
	fail = false
	if err := Apply(ctx, run, path, nil); err != nil {
		t.Fatal(err)
	}
}
func TestNoModesNeedsNoEttool(t *testing.T) {
	if err := Apply(context.Background(), func(context.Context, string, ...string) (string, error) {
		t.Fatal("unexpected command")
		return "", nil
	}, filepath.Join(t.TempDir(), "absent"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestBatchUnchangedPortsPersistsPartialProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.json")
	modes := map[string]string{"eth0": "100baseT/Full", "eth1": "100baseT/Full", "eth2": "100baseT/Full"}
	raw := strings.Replace(sample, "Advertised link modes: 100baseT/Full 1000baseT/Full", "Advertised link modes: 100baseT/Full", 1)
	readFailure := errors.New("port unavailable")
	var visited []string
	failAt := 3
	run := func(_ context.Context, command string, args ...string) (string, error) {
		if command != "ethtool" || len(args) != 1 {
			t.Fatalf("unexpected driver command %s %v", command, args)
		}
		visited = append(visited, args[0])
		if failAt == 3 && len(visited) == 2 {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("unchanged ports should share a journal write", err)
			}
		}
		if len(visited) == failAt {
			return "", readFailure
		}
		return raw, nil
	}
	check := func(want []string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var saved map[string]Settings
		if err := json.Unmarshal(data, &saved); err != nil || len(saved) != len(want) {
			t.Fatalf("journal %s, want %v: %v", data, want, err)
		}
		for _, name := range want {
			if !same(saved[name], Parse(raw)) {
				t.Fatalf("lost original settings for %s", name)
			}
		}
	}
	ctx := context.Background()
	if err := Apply(ctx, run, path, modes); !errors.Is(err, readFailure) {
		t.Fatal(err)
	}
	check(visited[:2])
	visited, failAt = nil, 0
	if err := Apply(ctx, run, path, modes); err != nil {
		t.Fatal(err)
	}
	check([]string{"eth0", "eth1", "eth2"})
	visited, failAt = nil, 2
	classNet := t.TempDir()
	for name := range modes {
		if err := os.Mkdir(filepath.Join(classNet, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := apply(ctx, run, path, nil, classNet); !errors.Is(err, readFailure) {
		t.Fatal(err)
	}
	delete(modes, visited[0])
	var remaining []string
	for name := range modes {
		remaining = append(remaining, name)
	}
	check(remaining)
	visited, failAt = nil, 0
	if err := Apply(ctx, run, path, nil); err != nil {
		t.Fatal(err)
	}
	check(nil)
}

func TestRestoreMissingPortRequiresConfirmedRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.json")
	classNet := t.TempDir()
	const saved = `{"eth9":{}}`
	if err := os.WriteFile(path, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	readFailure := errors.New("ethtool failed")
	calls := 0
	run := func(context.Context, string, ...string) (string, error) {
		calls++
		return "", readFailure
	}
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		ctx   context.Context
		modes map[string]string
		root  string
	}{
		{ctx, nil, filepath.Join(classNet, "unavailable")},
		{ctx, map[string]string{"eth9": ""}, classNet},
		{ctx, map[string]string{"eth9": "auto"}, classNet},
		{canceled, nil, classNet},
	} {
		if err := apply(tc.ctx, run, path, tc.modes, tc.root); !errors.Is(err, readFailure) {
			t.Fatalf("lost driver error: %v", err)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != saved {
			t.Fatalf("lost recovery data: %s, %v", raw, err)
		}
	}
	calls = 0
	for i := 0; i < 2; i++ {
		if err := apply(ctx, run, path, nil, classNet); err != nil {
			t.Fatal(err)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "{}" || calls != 1 {
			t.Fatalf("journal %s, calls %d, error %v", raw, calls, err)
		}
	}
}
