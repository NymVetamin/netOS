package config

import "testing"

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
