// Package awgruntime hosts the official AmneziaWG dataplane in a separate
// executable. Management and configuration stay in netosd.
package awgruntime

import "strings"

const SocketDir = "/run/netos/amneziawg"

func ValidInterface(name string) bool {
	if len(name) > 15 {
		return false
	}
	suffix := strings.TrimPrefix(name, "awg-ch")
	if suffix == name {
		suffix = strings.TrimPrefix(name, "awg-srv")
	}
	if suffix == name || suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
