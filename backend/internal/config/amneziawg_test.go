package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validAWG() AmneziaWGParams {
	return AmneziaWGParams{Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 25, H1: "100-200", H2: "300", H3: "400", H4: "500-600"}
}

// Values the kernel module accepts silently but that break obfuscation, and
// values it rejects (overlapping H, unknown tags) must fail before apply.
func TestAmneziaWGParamsValidate(t *testing.T) {
	if err := validAWG().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (AmneziaWGParams{}).Validate(); err != nil {
		t.Fatalf("plain defaults rejected: %v", err)
	}
	for name, change := range map[string]func(*AmneziaWGParams){
		"Jc over 128":        func(a *AmneziaWGParams) { a.Jc = 200 },
		"negative Jc":        func(a *AmneziaWGParams) { a.Jc = -1 },
		"Jmin over Jmax":     func(a *AmneziaWGParams) { a.Jmin, a.Jmax = 80, 70 },
		"Jmax over UDP":      func(a *AmneziaWGParams) { a.Jmax = 70000 },
		"S1 over UDP":        func(a *AmneziaWGParams) { a.S1 = 65507 },
		"equal sizes":        func(a *AmneziaWGParams) { a.S1, a.S2 = 10, 66 },
		"overlapping H":      func(a *AmneziaWGParams) { a.H2 = "150-250" },
		"H equal to default": func(a *AmneziaWGParams) { a.H1, a.H2 = "", "1" },
		"reversed range":     func(a *AmneziaWGParams) { a.H1 = "200-100" },
		"H not a number":     func(a *AmneziaWGParams) { a.H1 = "0x10" },
		"unknown tag":        func(a *AmneziaWGParams) { a.I1 = "<z 1>" },
		"tag with value":     func(a *AmneziaWGParams) { a.I1 = "<c 1>" },
		"odd hex":            func(a *AmneziaWGParams) { a.I1 = "<b 0xabc>" },
		"hex without 0x":     func(a *AmneziaWGParams) { a.I1 = "<b ab>" },
		"open tag":           func(a *AmneziaWGParams) { a.I1 = "<b 0xab" },
		"text outside tag":   func(a *AmneziaWGParams) { a.I1 = "abc" },
		"oversized packet":   func(a *AmneziaWGParams) { a.I1 = "<r 70000>" },
		"newline injection":  func(a *AmneziaWGParams) { a.I1 = "<t>\nPostUp = id" },
	} {
		a := validAWG()
		change(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Tags accepted by the kernel module (checked on Debian 13, amneziawg 3.1).
	a := validAWG()
	a.I1 = "<b 0xc0ffee><rc 4><rd 2><c><t><r 16><r 0>"
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAmneziaWGNativeLines(t *testing.T) {
	a := AmneziaWGParams{Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 25, H2: "300", I2: "<t>"}
	got := a.NativeLines()
	want := "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nS3 = 0\nS4 = 0\nH1 = 1\nH2 = 300\nH3 = 3\nH4 = 4\nI2 = <t>\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "I1 =") {
		t.Fatal("empty signature written; the native tools reject it")
	}
}

func messages(r *ValidationResult) string {
	var b strings.Builder
	for _, p := range r.Problems {
		if p.Severity == "error" {
			b.WriteString(p.Path + ": " + p.Message + "\n")
		}
	}
	return b.String()
}

func TestAmneziaWGChannelNeedsItsOwnComponent(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	build := func(components ...string) *Config {
		c := Default()
		for _, id := range components {
			c.Components = append(c.Components, Component{ID: id, Installed: true})
		}
		c.Channels = append(c.Channels, Channel{ID: "awg", Index: 1, Name: "AWG", Enabled: true, Type: "wireguard", Mode: "tun", FailMode: "block",
			Probe: DefaultProbe(), Config: map[string]any{"address": "10.44.0.2/32", "private_key": key, "peer_public_key": key,
				"endpoint": "vpn.example:51820", "allowed_ips": []string{"0.0.0.0/0"}, "amneziawg": map[string]any{"jc": 4, "jmin": 40, "jmax": 70}}})
		return c
	}
	if r := build("wireguard").Validate(); !strings.Contains(messages(r), "компонент «AmneziaWG»") {
		t.Fatalf("AmneziaWG channel accepted without its component: %v", r)
	}
	if r := build("amneziawg").Validate(); r.HasErrors() {
		t.Fatalf("AmneziaWG channel required plain WireGuard: %s", messages(r))
	}
	bad := build("amneziawg")
	bad.Channels[len(bad.Channels)-1].Config["amneziawg"] = map[string]any{"jmin": 80, "jmax": 70}
	if r := bad.Validate(); !strings.Contains(messages(r), "Jmin не может быть больше Jmax") {
		t.Fatalf("invalid obfuscation accepted: %v", r)
	}
	bad.Channels[len(bad.Channels)-1].Config["amneziawg"] = map[string]any{"jc": 4, "post_up": "id"}
	if r := bad.Validate(); !r.HasErrors() {
		t.Fatal("unknown obfuscation field accepted")
	}
}

// The exit through a client of an AmneziaWG server runs on that server's
// interface: it needs AmneziaWG, not the WireGuard component.
func TestAmneziaWGServerExitChannelNeedsNoWireGuard(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	c := Default()
	c.Components = []Component{{ID: "amneziawg", Installed: true}}
	c.VPNServers = []VPNServer{{ID: "s", Index: 1, Name: "AWG", Type: "wireguard", Enabled: true, Subnet: "10.88.0.1/24", Port: 51900, DefaultChannel: "direct",
		Config: map[string]any{"private_key": key, "amneziawg": map[string]any{"jc": 4, "jmin": 40, "jmax": 70}},
		Peers:  []VPNPeer{{ID: "vps", Name: "VPS", Enabled: true, Address: "10.88.0.2", UseAsChannel: true, Credentials: map[string]string{"public_key": key}}}}}
	c.Normalize()
	if r := c.Validate(); r.HasErrors() {
		t.Fatalf("exit of an AmneziaWG server rejected: %s", messages(r))
	}
	c.Components = nil
	if r := c.Validate(); !strings.Contains(messages(r), "компонент «AmneziaWG»") {
		t.Fatalf("server without its component accepted: %s", messages(r))
	}
}
