package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// BridgeCarrierNames returns the two hidden veth names used to give an empty
// bridge carrier. Short legacy names stay stable across upgrades. Long bridge
// names use a deterministic digest instead of truncation, which made distinct
// bridges with the same prefix fight over one carrier pair.
func BridgeCarrierNames(bridge string) (string, string) {
	base := strings.TrimPrefix(bridge, "br-")
	if len("d-"+base) <= maxInterfaceName {
		return "d-" + base, "p-" + base
	}
	sum := sha256.Sum256([]byte(bridge))
	suffix := fmt.Sprintf("%x", sum[:6])
	return "d-" + suffix, "p-" + suffix
}
