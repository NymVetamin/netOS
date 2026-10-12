package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRetainedWireGuardClientKeyValidation(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := validWGServerConfig()
	creds := cfg.VPNServers[0].Peers[0].Credentials
	creds["public_key"] = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, private := range []string{"", base64.StdEncoding.EncodeToString(key.Bytes()), "invalid", base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		creds["private_key"] = private
		invalid := false
		for _, p := range cfg.Validate().Problems {
			if strings.HasSuffix(p.Path, ".credentials.private_key") {
				invalid = true
			}
		}
		want := private != "" && private != base64.StdEncoding.EncodeToString(key.Bytes())
		if invalid != want {
			t.Fatalf("private key accepted/rejected incorrectly (invalid=%v want=%v)", invalid, want)
		}
	}
}
