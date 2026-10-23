package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestReservationBaseUsesPrivateBaselineAndPermissions(t *testing.T) {
	for _, section := range []string{"clients", "services", "system"} {
		t.Run(section, func(t *testing.T) {
			s, _, _, _ := transactionServer(t)
			base := config.Default()
			base.DHCP.Reservations = []config.Reservation{{ID: "original", MAC: "02:00:00:00:00:01", IP: "192.0.2.10", Comment: "keep", Hostname: "original"}}
			// The draft has removed the reservation. A page reload must still
			// retrieve its original metadata from this owner's baseline.
			s.privateDrafts = map[string]*privateDraft{"operator": {Base: base, Config: config.Default(), Version: 7}}
			w := httptest.NewRecorder()
			s.handleGetConfig(w, limitedRequest(map[string]string{section: "view"}))
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var got configResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if section == "system" {
				if len(got.BaseReservations) != 0 {
					t.Fatal("reservation metadata leaked")
				}
			} else if len(got.BaseReservations) != 1 || got.BaseReservations[0] != base.DHCP.Reservations[0] {
				t.Fatal("original reservation was not preserved")
			}
			if len(got.Config.DHCP.Reservations) != 0 {
				t.Fatal("baseline replaced the draft")
			}
		})
	}
}
