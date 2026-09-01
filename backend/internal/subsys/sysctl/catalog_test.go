package sysctl

import (
	"slices"
	"testing"
)

func TestManagedSysctlCatalogIsSortedUniqueAndComplete(t *testing.T) {
	keys := ManagedKeys()
	if len(keys) == 0 || !slices.IsSorted(keys) {
		t.Fatalf("managed keys are empty or unsorted: %v", keys)
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] {
			t.Fatalf("duplicate managed key %q", key)
		}
		seen[key] = true
	}
	for _, required := range []string{
		"net.ipv4.ip_forward",
		"net.ipv6.conf.all.disable_ipv6",
		"net.ipv6.conf.default.accept_ra",
	} {
		if !seen[required] {
			t.Fatalf("managed catalog lacks %q", required)
		}
	}
	perInterface := ManagedPerInterfaceIPv6Keys()
	if !slices.Equal(perInterface, []string{"accept_ra", "autoconf", "disable_ipv6"}) {
		t.Fatalf("per-interface catalog=%v", perInterface)
	}
	perInterface[0] = "mutated"
	if ManagedPerInterfaceIPv6Keys()[0] != "accept_ra" {
		t.Fatal("caller mutation escaped into the catalog")
	}
}
