package wifi

import (
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func RenderRadio(radio config.WiFiRadio, cfg *config.Config) ([]byte, error) {
	interfaces := map[string]string{}
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = cfg.InterfaceName(iface.ID)
	}
	bridges := map[string]string{}
	for _, network := range cfg.Networks {
		bridges[network.ID] = interfaces[network.Interface]
	}
	var ssids []config.WiFiSSID
	for _, ssid := range radio.SSIDs {
		if ssid.Enabled {
			ssids = append(ssids, ssid)
		}
	}
	if len(ssids) == 0 {
		return nil, fmt.Errorf("нет включённых Wi-Fi-сетей")
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Файл содержит секреты; права 0600.")
	fmt.Fprintf(&b, "interface=%s\nctrl_interface=/run/netos-hostapd-%s\ndriver=nl80211\n", radio.Device, radioToken(radio.ID))
	fmt.Fprintf(&b, "country_code=%s\nieee80211d=1\nchannel=%d\n", strings.ToUpper(radio.Country), radio.Channel)
	if radio.Band == "2.4" {
		fmt.Fprintln(&b, "hw_mode=g\nieee80211n=1")
	} else {
		fmt.Fprintln(&b, "hw_mode=a\nieee80211n=1\nieee80211ac=1")
	}
	if radio.Width == 40 || radio.Width == 80 {
		direction := secondaryChannelDirection(radio.Band, radio.Channel)
		fmt.Fprintf(&b, "ht_capab=[HT40%s]\n", direction)
	}
	if radio.Width == 80 {
		center := center80(radio.Channel)
		fmt.Fprintf(&b, "vht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=%d\n", center)
	}
	renderSSID(&b, ssids[0], bridges[ssids[0].Network])
	for i, ssid := range ssids[1:] {
		fmt.Fprintf(&b, "\nbss=%s-n%d\n", radio.Device, i+1)
		renderSSID(&b, ssid, bridges[ssid.Network])
	}
	return []byte(b.String()), nil
}

func secondaryChannelDirection(band string, channel int) string {
	if band == "2.4" {
		if channel > 7 {
			return "-"
		}
		return "+"
	}
	// Standard 5 GHz primary channels alternate their secondary channel
	// above/below inside each 80 MHz block.
	for _, lower := range []int{40, 48, 56, 64, 104, 112, 120, 128, 136, 144, 153, 161} {
		if channel == lower {
			return "-"
		}
	}
	if channel == 165 || channel == 173 {
		return "-"
	}
	return "+"
}

func renderSSID(b *strings.Builder, ssid config.WiFiSSID, bridge string) {
	fmt.Fprintf(b, "ssid=%s\nbridge=%s\nignore_broadcast_ssid=%d\nap_isolate=%d\n", ssid.SSID, bridge, boolInt(ssid.Hidden), boolInt(ssid.Isolate))
	switch ssid.Security {
	case "open":
		fmt.Fprintln(b, "auth_algs=1\nwpa=0")
	case "wpa2":
		fmt.Fprintf(b, "wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase=%s\n", ssid.Password)
	case "wpa3":
		fmt.Fprintf(b, "wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_password=%s\n", ssid.Password)
	case "wpa2/wpa3":
		fmt.Fprintf(b, "wpa=2\nwpa_key_mgmt=WPA-PSK SAE\nrsn_pairwise=CCMP\nieee80211w=1\nwpa_passphrase=%s\nsae_password=%s\n", ssid.Password, ssid.Password)
	}
}

func center80(channel int) int {
	for _, block := range [][3]int{{36, 48, 42}, {52, 64, 58}, {100, 112, 106}, {116, 128, 122}, {132, 144, 138}, {149, 161, 155}} {
		if channel >= block[0] && channel <= block[1] {
			return block[2]
		}
	}
	return channel
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func renderUnit(radio config.WiFiRadio, conf string) string {
	return `[Unit]
Description=netOS: Wi-Fi access point ` + radio.Device + `
After=network.target

[Service]
Type=simple
RuntimeDirectory=netos-hostapd-` + radioToken(radio.ID) + `
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/hostapd ` + conf + `
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`
}
