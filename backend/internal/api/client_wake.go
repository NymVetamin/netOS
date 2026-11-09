package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func wakePacket(address string) ([]byte, error) {
	mac, err := net.ParseMAC(address)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || string(mac) == string(make([]byte, 6)) {
		return nil, fmt.Errorf("нужен MAC-адрес Ethernet-устройства")
	}
	packet := make([]byte, 102)
	for i := 0; i < 6; i++ {
		packet[i] = 0xff
	}
	for i := 6; i < len(packet); i += 6 {
		copy(packet[i:], mac)
	}
	return packet, nil
}

func wakeInterface(cfg *config.Config, networkID string) (string, error) {
	if cfg != nil && networkID != "" {
		for _, network := range cfg.Networks {
			if network.ID == networkID {
				if network.Enabled {
					if iface, ok := cfg.InterfaceByID(network.Interface); ok && iface.Enabled && iface.Name != "" {
						return iface.Name, nil
					}
				}
				break
			}
		}
	}
	return "", fmt.Errorf("локальный сегмент недоступен; выберите включённый сегмент из применённых настроек")
}

func (s *Server) handleClientWake(w http.ResponseWriter, r *http.Request) {
	if !may(r, "clients", true) {
		writeError(w, http.StatusForbidden, "нет права управления клиентами")
		return
	}
	var input struct {
		MAC     string `json:"mac"`
		Network string `json:"network"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		writeError(w, 400, "некорректные параметры Wake-on-LAN")
		return
	}
	packet, err := wakePacket(input.MAC)
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	iface, err := wakeInterface(s.Engine.Current(), input.Network)
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	err = sendWakePacket(iface, packet)
	if s.Store != nil {
		detail := iface
		if err != nil {
			detail += ": " + err.Error()
		}
		_ = s.Store.Audit(store.AuditEntry{User: userOf(r), Action: "client-wake", Target: input.MAC, Detail: detail, Success: err == nil})
	}
	if err != nil {
		writeError(w, 500, "не удалось отправить Wake-on-LAN: %s", err)
		return
	}
	writeJSON(w, 200, map[string]string{"interface": iface})
}
