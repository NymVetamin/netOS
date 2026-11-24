package system

import (
	"os"
	"testing"
)

func TestRemoveLeftoverDaemonPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		removed       bool
	}{
		{"ours", daemonPolicyScript, true},
		{"edited", daemonPolicyScript + "# admin\n", false},
		{"foreign", "#!/bin/sh\nexit 101\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := withTestPolicyPath(t)
			if err := os.WriteFile(path, []byte(tc.content), 0755); err != nil {
				t.Fatal(err)
			}
			for range 2 { // repeat is harmless
				if err := RemoveLeftoverDaemonPolicy(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(path); os.IsNotExist(err) != tc.removed {
				t.Fatalf("removed=%v want %v", os.IsNotExist(err), tc.removed)
			}
		})
	}
	path := withTestPolicyPath(t)
	if err := RemoveLeftoverDaemonPolicy(); err != nil { // absent file
		t.Fatal(err)
	}
	release, err := holdDaemons()
	if err != nil {
		t.Fatal(err)
	}
	if err = RemoveLeftoverDaemonPolicy(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatalf("live hold lost its policy: %v", err)
	}
	release()
}
