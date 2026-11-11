package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestAmneziaWGOptions(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	for _, a := range []AmneziaWGOptions{
		{}, {HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{Jc: 4, Jmin: 40, Jmax: 70, S1: 12, S2: 13, S3: 14, S4: 15, H1: "100-200", H2: "300", H3: "400", H4: "500-600", I1: "<b 0xdeadbeef><r 10><rd 2><rc 3><t>", HeaderProtectionKey: key, ContentPaddingAddition: "0-32", RekeyAfterTime: "60-120"},
	} {
		if err := a.Validate(); err != nil {
			t.Fatal(err)
		}
		if got, again := a.NativeParameters(), a.NativeParameters(); got != again {
			t.Fatal("non-deterministic output")
		}
	}
	for name, a := range map[string]AmneziaWGOptions{
		"junk count": {Jc: 129}, "junk reversed": {Jmin: 50, Jmax: 1}, "negative padding": {S1: -1},
		"large padding": {S4: 4097}, "protection nonce": {HeaderProtectionKey: key},
		"invalid key": {HeaderProtectionKey: "secret-invalid"}, "overlap": {H1: "1-2"},
		"header injection": {H1: "7\nprivate_key=evil"}, "tag injection": {I1: "<r 1>\nPostUp=evil"},
		"unknown tag": {I1: "<x 1>"}, "tag overflow": {I1: "<r 65507><t>"},
		"bad bytes": {I1: "<b 0x0x>"}, "short bytes": {I1: "<b 0x1>"},
		"junk overflow": {Jmax: 65508}, "attempt overflow": {MaxHandshakeAttempts: "129"},
		"partial zero timeout": {RekeyTimeout: "0-1"}, "padding overflow": {ContentPaddingAddition: "4097"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := a.Validate(); err == nil {
				t.Fatal("invalid options accepted")
			} else if strings.Contains(err.Error(), "secret-invalid") {
				t.Fatal("secret in error")
			}
		})
	}
	reset := (AmneziaWGOptions{}).NativeParameters()
	for _, want := range []string{"Jc = 0\n", "H1 = 1\n", "H4 = 4\n", "I1 = \n", "HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", "RandomTrailers = false\n"} {
		if !strings.Contains(reset, want) {
			t.Fatalf("missing reset %q", want)
		}
	}
}

func TestAmneziaWGRange(t *testing.T) {
	for _, s := range []string{"0", "1-2", "4294967295", "1-4294967295"} {
		if _, _, err := AmneziaWGRange(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "-1", "+1", "2-1", "1-2-3", "1\n", "0-4294967295", "4294967296", strings.Repeat("9", 10000)} {
		if _, _, err := AmneziaWGRange(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestAmneziaWGHexKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	got, err := AmneziaWGHexKey(key)
	if err != nil || got != strings.Repeat("6b", 32) {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := AmneziaWGHexKey("secret-invalid"); err == nil || strings.Contains(err.Error(), "secret-invalid") {
		t.Fatal("invalid secret exposed or accepted")
	}
}

func BenchmarkAmneziaWGOptions(b *testing.B) {
	for _, tags := range []int{8, 4096} {
		b.Run(fmt.Sprint(tags), func(b *testing.B) {
			a := AmneziaWGOptions{I1: strings.Repeat("<r 1>", tags)}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := a.Validate(); err != nil {
					b.Fatal(err)
				}
				_ = a.NativeParameters()
			}
		})
	}
}
