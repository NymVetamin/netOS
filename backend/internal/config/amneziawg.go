package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// The pinned runtime uses bufio.Scanner's 64 KiB buffer for UAPI lines.
// Reserve four bytes for "iN=" and the terminating newline.
const AmneziaWGMaxSignatureLength = 64*1024 - 4

// AmneziaWGOptions contains protocol parameters, never shell commands. Keys
// shared with ordinary WireGuard remain on the channel/server configuration.
type AmneziaWGOptions struct {
	PersistentKeepalive    string `json:"persistent_keepalive,omitempty" plan:"Диапазон keepalive" sensitivity:"public"`
	Jc                     int    `json:"jc,omitempty" plan:"Jc" sensitivity:"public"`
	Jmin                   int    `json:"jmin,omitempty" plan:"Jmin" sensitivity:"public"`
	Jmax                   int    `json:"jmax,omitempty" plan:"Jmax" sensitivity:"public"`
	S1                     int    `json:"s1,omitempty" plan:"S1" sensitivity:"public"`
	S2                     int    `json:"s2,omitempty" plan:"S2" sensitivity:"public"`
	S3                     int    `json:"s3,omitempty" plan:"S3" sensitivity:"public"`
	S4                     int    `json:"s4,omitempty" plan:"S4" sensitivity:"public"`
	H1                     string `json:"h1,omitempty" plan:"H1" sensitivity:"public"`
	H2                     string `json:"h2,omitempty" plan:"H2" sensitivity:"public"`
	H3                     string `json:"h3,omitempty" plan:"H3" sensitivity:"public"`
	H4                     string `json:"h4,omitempty" plan:"H4" sensitivity:"public"`
	I1                     string `json:"i1,omitempty" plan:"I1" sensitivity:"public"`
	I2                     string `json:"i2,omitempty" plan:"I2" sensitivity:"public"`
	I3                     string `json:"i3,omitempty" plan:"I3" sensitivity:"public"`
	I4                     string `json:"i4,omitempty" plan:"I4" sensitivity:"public"`
	I5                     string `json:"i5,omitempty" plan:"I5" sensitivity:"public"`
	HeaderProtectionKey    string `json:"header_protection_key,omitempty" plan:"Ключ защиты заголовков" sensitivity:"secret"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty" plan:"Дополнение пакетов" sensitivity:"public"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty" plan:"Интервал обновления ключа" sensitivity:"public"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty" plan:"Повтор обмена ключами" sensitivity:"public"`
	RejectAfterTime        string `json:"reject_after_time,omitempty" plan:"Срок действия ключа" sensitivity:"public"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty" plan:"Таймаут keepalive" sensitivity:"public"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty" plan:"Попытки соединения" sensitivity:"public"`
	RandomTrailers         bool   `json:"random_trailers,omitempty" plan:"Случайные окончания пакетов" sensitivity:"public"`
	DisableCookies         bool   `json:"disable_cookies,omitempty" plan:"Отключение cookie-защиты" sensitivity:"public"`
}

// AmneziaWGRange accepts only the decimal syntax understood by the pinned
// runtime. Length is bounded before parsing; full uint32 ranges are rejected
// because their width cannot be represented by the runtime's random sampler.
func AmneziaWGRange(value string) (uint32, uint32, error) {
	if len(value) == 0 || len(value) > 21 {
		return 0, 0, fmt.Errorf("ожидается число или диапазон a-b")
	}
	loText, hiText, rangeSet := strings.Cut(value, "-")
	if !rangeSet {
		hiText = loText
	}
	parse := func(s string) (uint64, error) {
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("ожидаются десятичные цифры")
			}
		}
		return strconv.ParseUint(s, 10, 32)
	}
	lo, err := parse(loText)
	if err != nil {
		return 0, 0, fmt.Errorf("некорректное начало диапазона")
	}
	hi, err := parse(hiText)
	if err != nil || hi < lo || hi-lo == 1<<32-1 {
		return 0, 0, fmt.Errorf("некорректный диапазон")
	}
	return uint32(lo), uint32(hi), nil
}

// Validate checks sizes before the runtime allocates padding/junk packets.
// One handshake may emit at most 128 junk packets of at most 65507 bytes.
func (a AmneziaWGOptions) Validate() error {
	if a.PersistentKeepalive != "" {
		_, hi, err := AmneziaWGRange(a.PersistentKeepalive)
		if err != nil || hi > 65535 {
			return fmt.Errorf("AmneziaWG: некорректный диапазон keepalive")
		}
	}
	if a.Jc < 0 || a.Jc > 128 || a.Jmin < 0 || a.Jmax < a.Jmin || a.Jmax > 65507 {
		return fmt.Errorf("AmneziaWG: Jc должен быть 0–128, Jmin/Jmax — 0–65507 и Jmin ≤ Jmax")
	}
	protected := false
	if a.HeaderProtectionKey != "" {
		if len(a.HeaderProtectionKey) != 44 {
			return fmt.Errorf("AmneziaWG: некорректный ключ защиты заголовков")
		}
		key, err := base64.StdEncoding.DecodeString(a.HeaderProtectionKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("AmneziaWG: некорректный ключ защиты заголовков")
		}
		for _, b := range key {
			protected = protected || b != 0
		}
	}
	for i, n := range []int{a.S1, a.S2, a.S3, a.S4} {
		if n < 0 || n > 4096 {
			return fmt.Errorf("AmneziaWG: S%d должен быть 0–4096", i+1)
		}
		if protected && n < 12 {
			return fmt.Errorf("AmneziaWG: с ключом защиты заголовков S%d должен быть не меньше 12", i+1)
		}
	}
	var headers [4][2]uint32
	for i, h := range []string{a.H1, a.H2, a.H3, a.H4} {
		if h == "" {
			h = strconv.Itoa(i + 1)
		}
		lo, hi, err := AmneziaWGRange(h)
		if err != nil {
			return fmt.Errorf("AmneziaWG: H%d: %w", i+1, err)
		}
		headers[i] = [2]uint32{lo, hi}
		for j := 0; j < i; j++ {
			if lo <= headers[j][1] && headers[j][0] <= hi {
				return fmt.Errorf("AmneziaWG: диапазоны H%d и H%d пересекаются", j+1, i+1)
			}
		}
	}
	for i, signature := range []string{a.I1, a.I2, a.I3, a.I4, a.I5} {
		if err := validateAmneziaSignature(signature); err != nil {
			return fmt.Errorf("AmneziaWG: I%d: %w", i+1, err)
		}
	}
	for _, field := range []struct {
		name, value string
		max         uint32
	}{
		{"ContentPaddingAddition", a.ContentPaddingAddition, 4096},
		{"RekeyAfterTime", a.RekeyAfterTime, 1<<32 - 1}, {"RekeyTimeout", a.RekeyTimeout, 1<<32 - 1},
		{"RejectAfterTime", a.RejectAfterTime, 1<<32 - 1}, {"KeepaliveTimeout", a.KeepaliveTimeout, 1<<32 - 1},
		{"MaxHandshakeAttempts", a.MaxHandshakeAttempts, 128},
	} {
		if field.value == "" {
			continue
		}
		lo, hi, err := AmneziaWGRange(field.value)
		if err != nil || hi > field.max || field.name != "ContentPaddingAddition" && lo == 0 && hi != 0 {
			return fmt.Errorf("AmneziaWG: некорректный %s", field.name)
		}
	}
	return nil
}

func IsWireGuardType(kind string) bool { return kind == "wireguard" || kind == "amneziawg" }

func WireGuardPrefix(kind string) string {
	if kind == "amneziawg" {
		return "awg"
	}
	return "wg"
}

// WireGuardNativeOptions is shared by managed configs and exported profiles.
// Returning defaults is necessary to reset cleared live obfuscation settings.
func WireGuardNativeOptions(kind string, options *AmneziaWGOptions) (string, error) {
	if kind != "amneziawg" {
		if options != nil {
			return "", fmt.Errorf("параметры AmneziaWG недопустимы для WireGuard")
		}
		return "", nil
	}
	if options == nil {
		options = &AmneziaWGOptions{}
	}
	if err := options.Validate(); err != nil {
		return "", err
	}
	return options.NativeParameters(), nil
}

func validateAmneziaOptions(r *ValidationResult, path, kind string, options *AmneziaWGOptions) {
	if kind != "amneziawg" {
		if options != nil {
			r.errf(path, "параметры AmneziaWG требуют типа AmneziaWG")
		}
		return
	}
	if options == nil {
		return
	}
	if err := options.Validate(); err != nil {
		r.errf(path, "%v", err)
	}
}

// Parse tags without regexp backtracking or allocating the generated packet.
func validateAmneziaSignature(s string) error {
	if len(s) > AmneziaWGMaxSignatureLength {
		return fmt.Errorf("слишком длинная сигнатура")
	}
	size := uint64(0)
	for s != "" {
		if s[0] != '<' {
			return fmt.Errorf("ожидается тег <...>")
		}
		tag, rest, ok := strings.Cut(s[1:], ">")
		if !ok {
			return fmt.Errorf("незавершённый тег")
		}
		s = rest
		kind, value, _ := strings.Cut(tag, " ")
		switch kind {
		case "t":
			if tag != "t" {
				return fmt.Errorf("некорректный тег времени")
			}
			size += 4
		case "b":
			if !strings.HasPrefix(value, "0x") || len(value)%2 != 0 || len(value) == 2 {
				return fmt.Errorf("некорректные шестнадцатеричные байты")
			}
			for _, c := range value[2:] {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					return fmt.Errorf("некорректные шестнадцатеричные байты")
				}
			}
			size += uint64((len(value) - 2) / 2)
		case "r", "rd", "rc":
			lo, hi, err := AmneziaWGRange(value)
			if err != nil || lo != hi {
				return fmt.Errorf("некорректная длина случайных данных")
			}
			size += uint64(lo)
		default:
			return fmt.Errorf("неизвестный тег сигнатуры")
		}
		if size > 65507 {
			return fmt.Errorf("сигнатура превышает размер UDP-пакета")
		}
	}
	return nil
}

// NativeParameters uses syntax accepted by the official native tools. Empty
// signatures are omitted; the controller restores their reset semantics.
// Only callers exporting a profile may
// expose the header-protection key to an authorized client.
func (a AmneziaWGOptions) NativeParameters() string {
	var b strings.Builder
	for _, f := range []struct {
		name string
		n    int
	}{
		{"Jc", a.Jc}, {"Jmin", a.Jmin}, {"Jmax", a.Jmax}, {"S1", a.S1}, {"S2", a.S2}, {"S3", a.S3}, {"S4", a.S4},
	} {
		fmt.Fprintf(&b, "%s = %d\n", f.name, f.n)
	}
	for i, v := range []string{a.H1, a.H2, a.H3, a.H4} {
		if v == "" {
			v = strconv.Itoa(i + 1)
		}
		fmt.Fprintf(&b, "H%d = %s\n", i+1, v)
	}
	for i, v := range []string{a.I1, a.I2, a.I3, a.I4, a.I5} {
		if v != "" {
			fmt.Fprintf(&b, "I%d = %s\n", i+1, v)
		}
	}
	key := a.HeaderProtectionKey
	if key == "" {
		key = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}
	fmt.Fprintf(&b, "HeaderProtectionKey = %s\n", key)
	for _, f := range []struct{ name, value string }{
		{"ContentPaddingAddition", a.ContentPaddingAddition}, {"RekeyAfterTime", a.RekeyAfterTime},
		{"RekeyTimeout", a.RekeyTimeout}, {"RejectAfterTime", a.RejectAfterTime},
		{"KeepaliveTimeout", a.KeepaliveTimeout}, {"MaxHandshakeAttempts", a.MaxHandshakeAttempts},
	} {
		v := f.value
		if v == "" {
			v = "0"
		}
		fmt.Fprintf(&b, "%s = %s\n", f.name, v)
	}
	for _, field := range []struct {
		name    string
		enabled bool
	}{{"RandomTrailers", a.RandomTrailers}, {"DisableCookies", a.DisableCookies}} {
		value := 0
		if field.enabled {
			value = 1
		}
		fmt.Fprintf(&b, "%s = %d\n", field.name, value)
	}
	return b.String()
}

// AmneziaWGHexKey converts native profile keys into UAPI keys without exposing
// the supplied secret in errors. Shared by the local controller and tests.
func AmneziaWGHexKey(value string) (string, error) {
	if len(value) != 44 {
		return "", fmt.Errorf("некорректный ключ AmneziaWG")
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("некорректный ключ AmneziaWG")
	}
	return hex.EncodeToString(key), nil
}
