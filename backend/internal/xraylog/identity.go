package xraylog

// ValidIdentity bounds event metadata to a configured server ID and protocol.
// The ID alphabet matches config object IDs and needs no systemd escaping.
// Mutable names must not be included: journal stream metadata survives reload.
func ValidIdentity(id, protocol string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	switch protocol {
	case "reality", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "socks", "http":
		return true
	}
	return false
}
