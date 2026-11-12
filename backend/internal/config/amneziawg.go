package config

import (
	"fmt"
	"strconv"
	"strings"
)

// AmneziaWGParams — параметры маскировки AmneziaWG в составе стандартного
// профиля AmneziaVPN. Канал или сервер WireGuard с ними работает на модуле
// amneziawg; всё остальное (ключи, адреса, маршруты) общее с WireGuard.
//
// Модуль ядра не проверяет смысл значений: Jmin больше Jmax, Jc = 200 и
// S1 = 2000 принимаются молча, и маскировка тихо ломается. Поэтому границы
// держит Validate. Сам модуль отвергает только неизвестные теги I и
// пересекающиеся диапазоны H — они тоже проверяются здесь, до применения.
type AmneziaWGParams struct {
	Jc   int    `json:"jc" plan:"Jc — число мусорных пакетов" sensitivity:"public"`
	Jmin int    `json:"jmin" plan:"Jmin — минимальный размер мусорного пакета" sensitivity:"public"`
	Jmax int    `json:"jmax" plan:"Jmax — максимальный размер мусорного пакета" sensitivity:"public"`
	S1   int    `json:"s1" plan:"S1 — дополнение начала рукопожатия" sensitivity:"public"`
	S2   int    `json:"s2" plan:"S2 — дополнение ответа рукопожатия" sensitivity:"public"`
	S3   int    `json:"s3,omitempty" plan:"S3 — дополнение cookie" sensitivity:"public"`
	S4   int    `json:"s4,omitempty" plan:"S4 — дополнение пакетов данных" sensitivity:"public"`
	H1   string `json:"h1" plan:"H1 — тип начала рукопожатия" sensitivity:"public"`
	H2   string `json:"h2" plan:"H2 — тип ответа рукопожатия" sensitivity:"public"`
	H3   string `json:"h3" plan:"H3 — тип cookie" sensitivity:"public"`
	H4   string `json:"h4" plan:"H4 — тип пакета данных" sensitivity:"public"`
	I1   string `json:"i1,omitempty" plan:"I1 — сигнатура" sensitivity:"public"`
	I2   string `json:"i2,omitempty" plan:"I2 — сигнатура" sensitivity:"public"`
	I3   string `json:"i3,omitempty" plan:"I3 — сигнатура" sensitivity:"public"`
	I4   string `json:"i4,omitempty" plan:"I4 — сигнатура" sensitivity:"public"`
	I5   string `json:"i5,omitempty" plan:"I5 — сигнатура" sensitivity:"public"`
}

// Sizes of the WireGuard messages each padding is added to, and the largest
// UDP payload: a padded message must still fit into one datagram.
const (
	amneziaMaxUDPPayload = 65507
	amneziaMaxJunk       = 128
)

// AmneziaWGRange parses "n" or "lo-hi" in decimal, the syntax of the native
// tools. Length is bounded before parsing.
func AmneziaWGRange(value string) (uint32, uint32, error) {
	if value == "" || len(value) > 21 {
		return 0, 0, fmt.Errorf("ожидается число или диапазон a-b")
	}
	loText, hiText, isRange := strings.Cut(value, "-")
	if !isRange {
		hiText = loText
	}
	parse := func(s string) (uint64, error) {
		if s == "" {
			return 0, fmt.Errorf("пусто")
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("ожидаются десятичные цифры")
			}
		}
		return strconv.ParseUint(s, 10, 32)
	}
	lo, err := parse(loText)
	if err != nil {
		return 0, 0, fmt.Errorf("ожидается число или диапазон a-b")
	}
	hi, err := parse(hiText)
	if err != nil || hi < lo {
		return 0, 0, fmt.Errorf("ожидается число или диапазон a-b, где a ≤ b")
	}
	return uint32(lo), uint32(hi), nil
}

// Validate проверяет параметры до того, как они попадут в модуль ядра.
func (a AmneziaWGParams) Validate() error {
	if a.Jc < 0 || a.Jc > amneziaMaxJunk {
		return fmt.Errorf("Jc должен быть от 0 до %d", amneziaMaxJunk)
	}
	if a.Jmin < 0 || a.Jmax < 0 || a.Jmax > amneziaMaxUDPPayload {
		return fmt.Errorf("Jmin и Jmax должны быть от 0 до %d", amneziaMaxUDPPayload)
	}
	if a.Jmin > a.Jmax {
		return fmt.Errorf("Jmin не может быть больше Jmax")
	}
	for i, pad := range []struct{ value, message int }{{a.S1, 148}, {a.S2, 92}, {a.S3, 64}, {a.S4, 32}} {
		if pad.value < 0 || pad.value+pad.message > amneziaMaxUDPPayload {
			return fmt.Errorf("S%d должен быть от 0 до %d", i+1, amneziaMaxUDPPayload-pad.message)
		}
	}
	// With S1+56 == S2 the padded initiation and response have equal length,
	// which is exactly the fingerprint padding exists to remove.
	if a.S1+56 == a.S2 {
		return fmt.Errorf("S1 + 56 не должно равняться S2: начало и ответ рукопожатия совпадут по размеру")
	}
	var headers [4][2]uint32
	for i, h := range a.headers() {
		lo, hi, err := AmneziaWGRange(h)
		if err != nil {
			return fmt.Errorf("H%d: %w", i+1, err)
		}
		headers[i] = [2]uint32{lo, hi}
		for j := 0; j < i; j++ {
			if lo <= headers[j][1] && headers[j][0] <= hi {
				return fmt.Errorf("H%d и H%d пересекаются: типы пакетов должны различаться", j+1, i+1)
			}
		}
	}
	for i, signature := range a.signatures() {
		if err := validateAmneziaSignature(signature); err != nil {
			return fmt.Errorf("I%d: %w", i+1, err)
		}
	}
	return nil
}

func (a AmneziaWGParams) headers() []string {
	out := []string{a.H1, a.H2, a.H3, a.H4}
	for i, h := range out {
		if h == "" { // standard WireGuard message types
			out[i] = strconv.Itoa(i + 1)
		}
	}
	return out
}

func (a AmneziaWGParams) signatures() []string { return []string{a.I1, a.I2, a.I3, a.I4, a.I5} }

// NativeLines — строки секции [Interface] для awg и профилей AmneziaVPN.
// Числа и типы пишутся всегда, сигнатуры — только заданные: пустую строку
// «I1 =» утилита отвергает, а снятую сигнатуру syncconf оставляет в ядре,
// поэтому смена маскировки пересоздаёт интерфейс.
func (a AmneziaWGParams) NativeLines() string {
	var b strings.Builder
	for _, f := range []struct {
		name  string
		value int
	}{{"Jc", a.Jc}, {"Jmin", a.Jmin}, {"Jmax", a.Jmax}, {"S1", a.S1}, {"S2", a.S2}, {"S3", a.S3}, {"S4", a.S4}} {
		fmt.Fprintf(&b, "%s = %d\n", f.name, f.value)
	}
	for i, h := range a.headers() {
		fmt.Fprintf(&b, "H%d = %s\n", i+1, h)
	}
	for i, signature := range a.signatures() {
		if signature != "" {
			fmt.Fprintf(&b, "I%d = %s\n", i+1, signature)
		}
	}
	return b.String()
}

// AmneziaWGConfLines extracts the obfuscation lines of a rendered native
// configuration. Equal results mean syncconf can update the live link; any
// difference requires recreating it, because syncconf keeps parameters
// that are merely absent from the file.
func AmneziaWGConfLines(conf string) string {
	var b strings.Builder
	for _, line := range strings.Split(conf, "\n") {
		key, _, _ := strings.Cut(line, " = ")
		switch key {
		case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5":
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// validateAmneziaSignature parses the tag syntax of the native tools without
// regexp backtracking: <b 0xHEX> bytes, <r N>/<rd N>/<rc N> random data, <t>
// timestamp, <c> counter. The resulting packet must fit one UDP datagram.
func validateAmneziaSignature(s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("сигнатура не может содержать перевод строки")
	}
	size := 0
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
		case "t", "c":
			if tag != kind {
				return fmt.Errorf("тег <%s> не принимает значения", kind)
			}
			size += 4
		case "b":
			hex, ok := strings.CutPrefix(value, "0x")
			if !ok || hex == "" || len(hex)%2 != 0 {
				return fmt.Errorf("ожидаются байты вида <b 0x0a1b>")
			}
			for _, c := range hex {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					return fmt.Errorf("ожидаются байты вида <b 0x0a1b>")
				}
			}
			size += len(hex) / 2
		case "r", "rd", "rc":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > amneziaMaxUDPPayload {
				return fmt.Errorf("длина случайных данных <%s N> должна быть от 0 до %d", kind, amneziaMaxUDPPayload)
			}
			size += n
		default:
			return fmt.Errorf("неизвестный тег <%s>", kind)
		}
		if size > amneziaMaxUDPPayload {
			return fmt.Errorf("сигнатура не помещается в один UDP-пакет")
		}
	}
	return nil
}
