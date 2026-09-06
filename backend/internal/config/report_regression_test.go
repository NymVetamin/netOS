package config

import "testing"

func TestReport1953BondMemberMTU(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces[2].Type = "bond"
	cfg.Interfaces[2].MTU = 1400
	cfg.Interfaces[1].MTU = 1442
	if !problem(t, cfg, "members", "MTU") {
		t.Fatal("incompatible bond MTU accepted")
	}
	cfg.Interfaces[1].MTU = 1400
	if problem(t, cfg, "members", "MTU") {
		t.Fatal("matching MTU rejected")
	}
}

func TestReportBondMemberMACRejectedBeforeApply(t *testing.T) {
	cfg := lanConfig()
	cfg.Interfaces[2].Type = "bond"
	cfg.Interfaces[1].MAC = "fa:16:3e:df:02:6c"
	if !problem(t, cfg, "members", "MAC") {
		t.Fatal("bond member MAC accepted")
	}
	cfg.Interfaces[1].MAC = ""
	cfg.Interfaces[2].MAC = "fa:16:3e:df:02:6c"
	if problem(t, cfg, "members", "MAC") {
		t.Fatal("bond MAC rejected")
	}
}
