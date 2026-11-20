package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagedACMEExistingAccountConflict(t *testing.T) {
	const domain = "router.example.org"
	issuer, err := newManagedIssuer(t.TempDir(), domain, "net@example.org")
	if err != nil {
		t.Fatal(err)
	}
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Replay-Nonce", "nonce")
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, base+"/nonce", base+"/account", base+"/order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			var envelope struct{ Payload string }
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
				http.Error(w, "invalid JWS", http.StatusBadRequest)
				return
			}
			data, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
			var lookup struct{ OnlyReturnExisting bool }
			if err != nil || json.Unmarshal(data, &lookup) != nil {
				t.Error("invalid account payload")
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			if !lookup.OnlyReturnExisting {
				http.Error(w, "already exists", http.StatusConflict)
				return
			}
			w.Header().Set("Location", base+"/existing")
			fmt.Fprint(w, `{"status":"valid"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ca.Close()
	issuer.client.DirectoryURL = ca.URL + "/directory"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := issuer.register(ctx); err != nil || string(issuer.client.KID) != ca.URL+"/existing" {
		t.Fatalf("account recovery: kid=%q err=%v", issuer.client.KID, err)
	}
}

func TestManagedACMEAccountKeySharedByConcurrentDomains(t *testing.T) {
	dir := t.TempDir()
	const count = 12
	start := make(chan struct{})
	type result struct {
		key []byte
		err error
	}
	results := make(chan result, count)
	for i := 0; i < count; i++ {
		issuer, err := newManagedIssuer(dir, "router.example.org", "net@example.org")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			<-start
			key, err := issuer.accountKey(context.Background())
			var der []byte
			if err == nil {
				der, err = x509.MarshalPKIXPublicKey(key.Public())
			}
			results <- result{der, err}
		}()
	}
	close(start)
	var first []byte
	for i := 0; i < count; i++ {
		res := <-results
		if res.err != nil {
			t.Fatal(res.err)
		}
		if first == nil {
			first = res.key
		} else if !bytes.Equal(first, res.key) {
			t.Fatal("issuers sharing one account used different keys")
		}
	}
}

func TestManagedACMECloseCancelsRenewal(t *testing.T) {
	const domain = "router.example.org"
	issuer, err := newManagedIssuer(t.TempDir(), domain, "net@example.org")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(37), DNSNames: []string{domain},
		NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := issuer.cache.Put(ctx, domain, data); err != nil {
		t.Fatal(err)
	}
	requested, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested <- struct{}{}
		select {
		case <-r.Context().Done():
			stopped <- struct{}{}
		case <-ctx.Done():
		}
	}))
	defer ca.Close()
	issuer.client.DirectoryURL = ca.URL
	defer issuer.Close()
	for i := 0; i < 2; i++ {
		cert, err := issuer.Certificate(ctx)
		if err != nil || cert.Leaf.SerialNumber.Int64() != 37 {
			t.Fatalf("cached certificate unavailable: %v", err)
		}
		if i == 0 {
			select {
			case <-requested:
			case <-ctx.Done():
				t.Fatal("no renewal request")
			}
		}
	}
	issuer.Close()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("authority request survived closing the issuer")
	}
}
