package config

import "testing"

func TestSystemValidationRejectsUnsafeCommitTimeout(t *testing.T) {
	for _, timeout := range []int{-1, 0, 86401} {
		cfg := Default()
		cfg.System.Panel.CommitTimeout = timeout
		cfg.Normalize()
		if result := cfg.Validate(); !hasErrorAt(result, "system.panel.commit_timeout") {
			t.Fatalf("commit timeout %d accepted: %#v", timeout, result.Problems)
		}
	}
}

func TestNormalizeBackfillsCommitTimeoutForLegacySchema(t *testing.T) {
	cfg := Default()
	cfg.Version = Version - 1
	cfg.System.Panel.CommitTimeout = 0
	cfg.Normalize()
	if cfg.System.Panel.CommitTimeout != 30 {
		t.Fatalf("legacy commit timeout = %d, want 30", cfg.System.Panel.CommitTimeout)
	}
}

func TestSystemValidationAllowsShortPositiveCommitTimeoutWithWarning(t *testing.T) {
	cfg := Default()
	cfg.System.Panel.CommitTimeout = 1
	result := cfg.Validate()
	if hasErrorAt(result, "system.panel.commit_timeout") {
		t.Fatalf("short positive timeout rejected: %#v", result.Problems)
	}
}

func TestComponentValidationRejectsDuplicateDesiredState(t *testing.T) {
	cfg := Default()
	cfg.Components = []Component{
		{ID: "xray", Installed: true},
		{ID: "xray", Installed: false},
	}
	if result := cfg.Validate(); !hasErrorAt(result, "components[1].id") {
		t.Fatalf("duplicate component accepted: %#v", result.Problems)
	}
}
