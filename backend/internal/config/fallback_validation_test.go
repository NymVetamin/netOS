package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestFallbackValidationSharedTailsAndFreshChanges(t *testing.T) {
	c := Default()
	c.Channels = nil
	for i, id := range []string{"a", "b", "c"} {
		c.Channels = append(c.Channels, Channel{ID: id, Index: i + 1, Enabled: true, Type: "direct", Mode: "tun", FailMode: "block"})
	}
	c.Channels[0].FailMode = "fallback"
	c.Channels[0].Fallback = "b"
	c.Channels[1].FailMode = "fallback"
	c.Channels[1].Fallback = "c"
	check := func(messages ...string) {
		t.Helper()
		var r ValidationResult
		c.validateChannels(&r)
		var want []Problem
		for _, msg := range messages {
			want = append(want, Problem{Path: "channels", Severity: "error", Message: msg})
		}
		if !reflect.DeepEqual(r.Problems, want) {
			t.Fatalf("got %#v want %#v", r.Problems, want)
		}
	}
	check()
	c.Channels[2].FailMode = "fallback"
	c.Channels[2].Fallback = "gone"
	missing := `канал "c" ссылается на несуществующий запасной "gone"`
	check(missing, missing, missing)
	c.Channels[2].Enabled = false
	disabled := `канал "b" ссылается на выключенный запасной "c"`
	check(disabled, disabled, missing)
	c.Channels[2].Enabled = true
	c.Channels[2].Fallback = "a"
	cycle := func(id string) string {
		return fmt.Sprintf("цикл в цепочке запасных каналов, начиная с %q", id)
	}
	check(cycle("a"), cycle("b"), cycle("c"))
	c.Channels[2].Enabled = false
	check(disabled, disabled, disabled)
	c.Channels[2].Enabled = true
	c.Channels[2].FailMode = "block"
	c.Channels[2].Fallback = ""
	check()
	c.Channels[1].FailMode = "direct"
	c.Channels[1].Fallback = "gone"
	check()
}
func TestFallbackValidationDuplicateStartingObjects(t *testing.T) {
	c := Default()
	c.Channels = []Channel{
		{ID: "a", Index: 1, Enabled: true, Type: "direct", Mode: "tun", FailMode: "fallback", Fallback: "gone"},
		{ID: "b", Index: 2, Enabled: true, Type: "direct", Mode: "tun", FailMode: "fallback", Fallback: "a"},
		{ID: "a", Index: 3, Enabled: true, Type: "direct", Mode: "tun", FailMode: "block"},
	}
	var r ValidationResult
	c.validateChannels(&r)
	want := []Problem{{Path: "channels[2].id", Severity: "error", Message: `дубликат идентификатора канала "a"`}, {Path: "channels", Severity: "error", Message: `канал "a" ссылается на несуществующий запасной "gone"`}}
	if !reflect.DeepEqual(r.Problems, want) {
		t.Fatalf("got %#v want %#v", r.Problems, want)
	}
}
func TestFallbackValidationSelfReferencePrecedence(t *testing.T) {
	c := Default()
	c.Channels = []Channel{{ID: "a", Index: 1, Enabled: true, Type: "direct", Mode: "tun", FailMode: "fallback", Fallback: "a"}}
	for _, enabled := range []bool{true, false, true} {
		c.Channels[0].Enabled = enabled
		var r ValidationResult
		c.validateChannels(&r)
		message := `цикл в цепочке запасных каналов, начиная с "a"`
		if !enabled {
			message = `канал "a" ссылается на выключенный запасной "a"`
		}
		want := []Problem{{Path: "channels[0].fallback", Severity: "error", Message: "канал не может быть запасным сам себе"}, {Path: "channels", Severity: "error", Message: message}}
		if !reflect.DeepEqual(r.Problems, want) {
			t.Fatalf("enabled=%t got %#v want %#v", enabled, r.Problems, want)
		}
	}
}
