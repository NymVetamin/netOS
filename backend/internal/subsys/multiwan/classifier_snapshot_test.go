package multiwan

import (
	"context"
	"strings"
	"testing"
)

func TestCLIClassifierUsesPersistedDesiredHealthState(t *testing.T) {
	dir := t.TempDir()
	cfg := balanceConfig()
	cfg.MultiWAN.Mode = "balance"
	c := New(&fakeRunner{}, dir, nil)
	c.states = map[string]*linkState{cfg.WANs[0].ID: {Down: true}}
	if err := c.reconcileBalanceClassifier(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	want := c.ClassifierRules(cfg)
	cli := New(&fakeRunner{}, dir, nil)
	if got := cli.ClassifierRules(cfg); got != want {
		t.Fatal("CLI forgot controller health state")
	}
	cfg.WANs[0].Weight++
	if got := cli.ClassifierRules(cfg); got == want || !strings.Contains(got, "--probability") {
		t.Fatal("old snapshot used for different config")
	}
}
