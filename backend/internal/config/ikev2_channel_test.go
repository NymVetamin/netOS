package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

func TestIKEv2ComponentIncludesEAPIdentity(t *testing.T) {
	component, ok := ComponentByID("strongswan")
	if !ok || !slices.Contains(component.Packages, "libcharon-extra-plugins") || !slices.Contains(component.Packages, "libcharon-extauth-plugins") {
		t.Fatalf("IKEv2 component must install EAP-Identity and EAP-MSCHAPv2 plugins: %+v", component.Packages)
	}
}

func testIKEv2CA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "QA CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestIKEv2ChannelValidationAndPolicyUse(t *testing.T) {
	cfg := Default()
	cfg.Components = append(cfg.Components, Component{ID: "strongswan", Installed: true})
	cfg.Channels = append(cfg.Channels, Channel{ID: "ike", Index: 1, Name: "IKEv2", Type: "ikev2", Enabled: true,
		Mode: "tun", FailMode: "block", Config: map[string]any{"server": "vpn.example.com", "server_identity": "vpn.example.com", "username": "alice", "password": "strong-password", "ca_cert": testIKEv2CA(t), "mtu": 1380}})
	if !cfg.usableChannelIDs()["ike"] {
		t.Fatal("IKEv2 channel unavailable to policy routing")
	}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("valid IKEv2 channel rejected: %+v", result.Problems)
	}
	for _, tc := range []struct{ field, value string }{{"server", "bad\nname"}, {"username", "alice\nadmin"}, {"ca_cert", "invalid"}} {
		broken := *cfg
		broken.Channels = append([]Channel(nil), cfg.Channels...)
		broken.Channels[1].Config = map[string]any{}
		for k, v := range cfg.Channels[1].Config {
			broken.Channels[1].Config[k] = v
		}
		broken.Channels[1].Config[tc.field] = tc.value
		if !hasErrorAt(broken.Validate(), "channels[1].config."+tc.field) {
			t.Fatalf("invalid %s accepted", tc.field)
		}
	}
}
