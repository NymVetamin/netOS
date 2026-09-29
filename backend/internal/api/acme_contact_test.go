package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestProductionACMEManagerSendsEmailInNewAccountPayload(t *testing.T) {
	contact := make(chan []string, 1)
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2U")
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, base+"/nonce", base+"/account", base+"/order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			var jws struct{ Payload string }
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Error(err)
				http.Error(w, "bad JWS", 400)
				return
			}
			raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err != nil {
				t.Error(err)
				http.Error(w, "bad payload", 400)
				return
			}
			var payload struct {
				Contact []string `json:"contact"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Error(err)
				http.Error(w, "bad account", 400)
				return
			}
			contact <- payload.Contact
			w.Header().Set("Location", base+"/account/1")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"status":"valid"}`)
		case "/order":
			// Account registration is the subject of this test, not issuance.
			http.Error(w, "order deliberately unavailable", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	manager, err := newProductionACMEManager(t.TempDir(), "router.example.test", "qa@example.test")
	if err != nil {
		t.Fatal(err)
	}
	m := manager.(*autocert.Manager)
	m.Client.DirectoryURL = base + "/directory"
	_, _ = m.GetCertificate(&tls.ClientHelloInfo{ServerName: "router.example.test"})
	select {
	case got := <-contact:
		if len(got) != 1 || got[0] != "mailto:qa@example.test" {
			t.Fatalf("wire contact=%v", got)
		}
	default:
		t.Fatal("no newAccount request captured")
	}
}
