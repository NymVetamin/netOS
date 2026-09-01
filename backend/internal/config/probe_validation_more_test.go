package config

import "testing"

func validProbeOf(kind string, target string) Probe {
	return Probe{
		Enabled: true, Type: kind, Targets: []string{target},
		Interval: 1, Timeout: 1, FailThreshold: 1, RiseThreshold: 1,
	}
}

func TestProbeValidationAcceptsEverySupportedTargetFamily(t *testing.T) {
	for _, test := range []struct {
		name  string
		probe Probe
	}{
		{"disabled empty probe", Probe{}},
		{"ICMP IPv4", validProbeOf("icmp", "192.0.2.1")},
		{"ICMP IPv6", validProbeOf("icmp", "2001:db8::1")},
		{"TCP DNS", validProbeOf("tcp", "example.com:443")},
		{"TCP IPv4", validProbeOf("tcp", "192.0.2.1:53")},
		{"TCP IPv6", validProbeOf("tcp", "[2001:db8::1]:443")},
		{"HTTP", validProbeOf("http", "http://example.com/health")},
		{"HTTPS IPv6", validProbeOf("http", "https://[2001:db8::1]:8443/health?full=1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := &ValidationResult{}
			validateProbe(result, "probe", test.probe)
			if result.HasErrors() {
				t.Fatalf("valid probe rejected: %+v", result.Problems)
			}
		})
	}
}

func TestProbeValidationRejectsEveryMalformedField(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		probe Probe
	}{
		{"unknown type", "probe.type", validProbeOf("dns", "192.0.2.1")},
		{"no targets", "probe.targets", Probe{Enabled: true, Type: "icmp", Interval: 1, Timeout: 1, FailThreshold: 1, RiseThreshold: 1}},
		{"bad ICMP", "probe.targets[0]", validProbeOf("icmp", "example.com")},
		{"TCP without port", "probe.targets[0]", validProbeOf("tcp", "example.com")},
		{"TCP empty host", "probe.targets[0]", validProbeOf("tcp", ":443")},
		{"TCP bad port", "probe.targets[0]", validProbeOf("tcp", "example.com:65536")},
		{"TCP control character", "probe.targets[0]", validProbeOf("tcp", "bad\nname:443")},
		{"HTTP without scheme", "probe.targets[0]", validProbeOf("http", "example.com/health")},
		{"HTTP without host", "probe.targets[0]", validProbeOf("http", "http:///health")},
		{"HTTP malformed port", "probe.targets[0]", validProbeOf("http", "https://example.com:%31")},
		{"interval low", "probe.interval", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.Interval = 0; return p }()},
		{"interval high", "probe.interval", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.Interval = 3601; return p }()},
		{"timeout low", "probe.timeout", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.Timeout = 0; return p }()},
		{"timeout high", "probe.timeout", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.Timeout = 61; return p }()},
		{"fail threshold low", "probe.fail_threshold", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.FailThreshold = 0; return p }()},
		{"fail threshold high", "probe.fail_threshold", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.FailThreshold = 101; return p }()},
		{"rise threshold low", "probe.rise_threshold", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.RiseThreshold = 0; return p }()},
		{"rise threshold high", "probe.rise_threshold", func() Probe { p := validProbeOf("icmp", "192.0.2.1"); p.RiseThreshold = 101; return p }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := &ValidationResult{}
			validateProbe(result, "probe", test.probe)
			if !hasErrorAt(result, test.path) {
				t.Fatalf("invalid probe accepted; expected %s: %+v", test.path, result.Problems)
			}
		})
	}
}
