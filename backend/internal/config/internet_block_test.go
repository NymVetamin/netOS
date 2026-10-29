package config

import "testing"

func TestInternetBlockClientChannelValidation(t *testing.T) {
	c := Default()
	c.Clients = []Client{{ID: "phone", MAC: "02:00:00:00:00:02", Channel: InternetBlockChannel}}
	if hasErrorAt(c.Validate(), "clients[0].channel") {
		t.Fatal("block rejected")
	}
	c.Clients[0].Channel = "missing"
	if !hasErrorAt(c.Validate(), "clients[0].channel") {
		t.Fatal("missing channel accepted")
	}
	c.Channels = append(c.Channels, Channel{ID: InternetBlockChannel, Enabled: true, Type: "direct"})
	if !hasErrorAt(c.Validate(), "channels[1].id") {
		t.Fatal("reserved channel id accepted")
	}
}
