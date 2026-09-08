package config

import "testing"

func TestValidTimezoneRequiresKnownLocation(t *testing.T) {
	for _, value := range []string{"UTC", "Europe/Moscow", "America/New_York", "Etc/GMT+3"} {
		if !validTimezone(value) {
			t.Errorf("known timezone %q rejected", value)
		}
	}
	for _, value := range []string{"Invalid/Nowhere", "Europe/Not_A_City", "Local", "", "../UTC"} {
		if validTimezone(value) {
			t.Errorf("invalid timezone %q accepted", value)
		}
	}
}
