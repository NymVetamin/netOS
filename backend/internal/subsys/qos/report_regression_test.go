package qos

import (
	"errors"
	"testing"
)

func TestReportMissingIngressHandle(t *testing.T) {
	if !missingTrafficObject(errors.New("tc qdisc del dev eth6 ingress: exit status 2: Error: Invalid handle.")) {
		t.Fatal("absent ingress rejected")
	}
	if missingTrafficObject(errors.New("Operation not permitted")) {
		t.Fatal("permission error ignored")
	}
}
