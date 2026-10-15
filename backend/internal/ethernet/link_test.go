package ethernet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Emulate a driver, retaining only the requested advertised modes. Checks that
// the durable original settings exist BEFORE the first write to the driver.
func driver(t *testing.T, path string, cur *Settings, writes *int, fail *bool) Run {
	return func(_ context.Context, cmd string, args ...string) (string, error) {
		t.Helper()
		if cmd != "ethtool" {
			t.Fatalf("command %s", cmd)
		}
		if len(args) > 1 {
			if _, err := os.Stat(path); err != nil {
				t.Fatal("baseline missing before mutation", err)
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
