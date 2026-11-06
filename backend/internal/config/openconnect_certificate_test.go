package config

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestOpenConnectCertificateValidation(t *testing.T) {
	cfg := validOpenConnectConfig()
	c := cfg.Channels[1].Config
	c["auth_mode"] = "certificate"
	c["client_certificate"] = base64.StdEncoding.EncodeToString([]byte("p12-fixture"))
	c["certificate_password"] = "container-password"
	delete(c, "username")
	delete(c, "password")
	if r := cfg.Validate(); r.HasErrors() {
		t.Fatal(r.Problems)
	}
	for _, tc := range []struct{ field, value string }{{"client_certificate", "bad"}, {"client_certificate", ""}, {"certificate_password", "bad\noption"}, {"auth_mode", "unknown"}} {
		old := c[tc.field]
		c[tc.field] = tc.value
		if !cfg.Validate().HasErrors() {
			t.Fatal("accepted", tc.field)
		}
		c[tc.field] = old
	}
	c["auth_mode"] = "both"
	if !cfg.Validate().HasErrors() {
		t.Fatal("combined auth needs account credentials")
	}
	c["username"] = "client"
	c["password"] = "account"
	if r := cfg.Validate(); r.HasErrors() {
		t.Fatal(r.Problems)
	}
}

func BenchmarkOpenConnectP12(b *testing.B) {
	for _, size := range []int{4096, 1024 * 1024} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			ch := Channel{Type: "openconnect", Config: map[string]any{"auth_mode": "certificate", "client_certificate": base64.StdEncoding.EncodeToString(make([]byte, size))}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				oc, err := ch.OpenConnectConfig()
				if err != nil {
					b.Fatal(err)
				}
				if _, err := oc.CertificateBytes(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
