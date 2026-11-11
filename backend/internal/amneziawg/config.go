// Package amneziawg adapts netOS configuration and lifecycle to the official
// AmneziaWG implementation. It does not implement the VPN protocol or crypto.
package amneziawg

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

type Peer struct {
	Key        string
	Values     map[string]string
	AllowedIPs []string
}

type State struct {
	Device map[string]string
	Peers  []Peer
}

type parameter struct{ key, kind string }

var options = map[string]parameter{
	"Jc": {"jc", "int"}, "Jmin": {"jmin", "int"}, "Jmax": {"jmax", "int"},
	"S1": {"s1", "int"}, "S2": {"s2", "int"}, "S3": {"s3", "int"}, "S4": {"s4", "int"},
	"H1": {"h1", "string"}, "H2": {"h2", "string"}, "H3": {"h3", "string"}, "H4": {"h4", "string"},
	"I1": {"i1", "string"}, "I2": {"i2", "string"}, "I3": {"i3", "string"}, "I4": {"i4", "string"}, "I5": {"i5", "string"},
	"HeaderProtectionKey":    {"header_protection_key", "key"},
	"ContentPaddingAddition": {"content_padding_addition", "string"},
	"RekeyAfterTime":         {"rekey_after_time", "string"}, "RekeyTimeout": {"rekey_timeout", "string"},
	"RejectAfterTime": {"reject_after_time", "string"}, "KeepaliveTimeout": {"keepalive_timeout", "string"},
	"MaxHandshakeAttempts": {"max_handshake_attempts", "string"},
	"RandomTrailers":       {"random_trailers", "bool"}, "DisableCookies": {"disable_cookies", "bool"},
}

// ParseNative accepts only protocol settings. Address/DNS, routes and scripts
// belong to netOS and cannot reach the control socket through this parser.
func ParseNative(ctx context.Context, text string) (State, error) {
	out := State{Device: map[string]string{}}
	if len(text) > 8<<20 {
		return out, fmt.Errorf("конфигурация AmneziaWG больше 8 МиБ")
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 132000)
	section := ""
	seen := map[string]bool{}
	keys := map[string]bool{}
	opt := map[string]any{}
	var peer *Peer
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[Interface]" {
			if section != "" {
				return out, fmt.Errorf("повторная секция Interface")
			}
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			if section == "" {
				return out, fmt.Errorf("сначала нужна секция Interface")
			}
			out.Peers = append(out.Peers, Peer{Values: map[string]string{}})
			peer = &out.Peers[len(out.Peers)-1]
			seen = map[string]bool{}
			section = "peer"
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || section == "" || seen[name] || strings.ContainsAny(value, "\x00\r\n") {
			return out, fmt.Errorf("некорректная или повторная строка AmneziaWG")
		}
		seen[name] = true
		if section == "interface" {
			if p, ok := options[name]; ok {
				switch p.kind {
				case "int":
					n, err := strconv.Atoi(value)
					if err != nil {
						return out, fmt.Errorf("некорректный %s", name)
					}
					opt[p.key] = n
					value = strconv.Itoa(n)
				case "bool":
					v, err := strconv.ParseBool(value)
					if err != nil {
						return out, fmt.Errorf("некорректный %s", name)
					}
					opt[p.key] = v
					if v {
						value = "1"
					} else {
						value = "0"
					}
				case "key":
					opt[p.key] = value
					var err error
					value, err = config.AmneziaWGHexKey(value)
					if err != nil {
						return out, err
					}
				default:
					opt[p.key] = value
				}
				out.Device[p.key] = value
				continue
			}
			switch name {
			case "PrivateKey":
				key, err := config.AmneziaWGHexKey(value)
				if err != nil {
					return out, err
				}
				// The official runtime clamps private keys before storing them.
				// Compare that representation to avoid writes on every repeat.
				if key != strings.Repeat("0", 64) {
					bytes, _ := hex.DecodeString(key)
					bytes[0] &= 248
					bytes[31] = bytes[31]&127 | 64
					key = hex.EncodeToString(bytes)
				}
				out.Device["private_key"] = key
			case "ListenPort":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return out, fmt.Errorf("некорректный ListenPort")
				}
				out.Device["listen_port"] = strconv.FormatUint(n, 10)
			case "FwMark":
				n, err := strconv.ParseUint(value, 0, 32)
				if err != nil {
					return out, fmt.Errorf("некорректный FwMark")
				}
				out.Device["fwmark"] = strconv.FormatUint(n, 10)
			default:
				return out, fmt.Errorf("неподдерживаемое поле Interface: %s", name)
			}
			continue
		}
		switch name {
		case "PublicKey":
			key, err := config.AmneziaWGHexKey(value)
			if err != nil {
				return out, err
			}
			if keys[key] {
				return out, fmt.Errorf("повторный публичный ключ клиента")
			}
			keys[key] = true
			peer.Key = key
		case "PresharedKey":
			key, err := config.AmneziaWGHexKey(value)
			if err != nil {
				return out, err
			}
			peer.Values["preshared_key"] = key
		case "Endpoint":
			endpoint, err := resolveEndpoint(ctx, value)
			if err != nil {
				return out, err
			}
			peer.Values["endpoint"] = endpoint
		case "PersistentKeepalive":
			lo, hi, err := config.AmneziaWGRange(value)
			if err != nil || hi > 65535 {
				return out, fmt.Errorf("некорректный PersistentKeepalive")
			}
			if lo == hi {
				value = strconv.FormatUint(uint64(lo), 10)
			}
			peer.Values["persistent_keepalive_interval"] = value
		case "AllowedIPs":
			prefixes := strings.Split(value, ",")
			unique := map[string]bool{}
			for _, raw := range prefixes {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
				if err != nil {
					return out, fmt.Errorf("некорректный AllowedIPs")
				}
				v := prefix.Masked().String()
				if !unique[v] {
					unique[v] = true
					peer.AllowedIPs = append(peer.AllowedIPs, v)
				}
			}
		default:
			return out, fmt.Errorf("неподдерживаемое поле Peer: %s", name)
		}
	}
	if scanner.Err() != nil {
		return out, fmt.Errorf("слишком длинная строка AmneziaWG")
	}
	if out.Device["private_key"] == "" {
		return out, fmt.Errorf("не указан PrivateKey")
	}
	for _, p := range out.Peers {
		if p.Key == "" {
			return out, fmt.Errorf("не указан PublicKey клиента")
		}
	}
	data, err := json.Marshal(opt)
	if err != nil {
		return out, err
	}
	var settings config.AmneziaWGOptions
	if err := json.Unmarshal(data, &settings); err != nil {
		return out, err
	}
	if err := settings.Validate(); err != nil {
		return out, err
	}
	// Native tools reject an empty I1= line. Absence still means reset in a
	// complete netOS configuration, so preserve that meaning in the UAPI delta.
	for _, key := range []string{"i1", "i2", "i3", "i4", "i5"} {
		if _, present := out.Device[key]; !present {
			out.Device[key] = ""
		}
	}
	for _, p := range options {
		value, present := out.Device[p.key]
		if !present || p.kind != "string" || strings.HasPrefix(p.key, "i") {
			continue
		}
		if value == "" {
			value = "0"
			if strings.HasPrefix(p.key, "h") {
				value = p.key[1:]
			}
		}
		lo, hi, err := config.AmneziaWGRange(value)
		if err != nil {
			return out, err
		}
		value = strconv.FormatUint(uint64(lo), 10)
		if hi != lo {
			value += "-" + strconv.FormatUint(uint64(hi), 10)
		}
		out.Device[p.key] = value
	}
	return out, nil
}

func resolveEndpoint(ctx context.Context, value string) (string, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("некорректный Endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("некорректный порт Endpoint")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		addresses, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if lookupErr != nil || len(addresses) == 0 {
			return "", fmt.Errorf("не удалось разрешить адрес Endpoint")
		}
		addr = addresses[0]
	}
	return netip.AddrPortFrom(addr, uint16(port)).String(), nil
}
