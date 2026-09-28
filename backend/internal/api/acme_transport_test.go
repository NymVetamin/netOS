package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/tlsutil"
	"golang.org/x/crypto/acme"
)

func TestACMEFinalizeWithoutLocationUsesOriginalOrderURI(t *testing.T) {
	certPath, _, _, err := tlsutil.EnsureSelfSigned(t.TempDir(), "router.example.test")
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2U")
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newOrder":%q}`, base+"/nonce", base+"/new")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/new":
			w.Header().Set("Location", base+"/orders/opaque-id")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"status":"ready","finalize":%q}`, base+"/finish/unrelated-id")
		case "/finish/unrelated-id":
			fmt.Fprint(w, `{"status":"processing"}`)
		case "/orders/opaque-id":
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, base+"/certificate")
		case "/certificate":
			w.Write(pem)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, patched := range []bool{false, true} {
		var transport http.RoundTripper = http.DefaultTransport
		if patched {
			transport = &acmeOrderTransport{base: transport}
		}
		client := &acme.Client{Key: key, KID: acme.KeyID(base + "/account"), DirectoryURL: base + "/directory", HTTPClient: &http.Client{Transport: transport}}
		order, err := client.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "router.example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		certs, _, err := client.CreateOrderCert(context.Background(), order.FinalizeURL, []byte("fixture-csr"), true)
		if patched && (err != nil || len(certs) == 0) {
			t.Fatalf("known order lost: %v", err)
		}
		if !patched && err == nil {
			t.Fatal("upstream no longer reproduces missing-Location failure; remove workaround")
		}
	}
}
