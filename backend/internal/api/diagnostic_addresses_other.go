//go:build !linux

package api

func diagnosticAddresses() (map[int][]string, error) { return nil, nil }
