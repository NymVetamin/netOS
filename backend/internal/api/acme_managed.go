package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/certificates"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// A managed issuer belongs to one domain and one account. The certificate
// manager serializes foreground calls; renewal and HTTP-01 run concurrently.
type managedIssuer struct {
	domain, email string
	cache         autocert.DirCache
	client        *acme.Client
	renewBefore   time.Duration
	cancel        context.CancelFunc
	done          chan struct{}
	order         chan struct{}
	mu            sync.RWMutex
	current       *tls.Certificate
	tokenPath     string
	tokenBody     string
}

func newManagedIssuer(cache, domain, email string) (*managedIssuer, error) {
	if err := secureACMECacheDir(cache); err != nil {
		return nil, err
	}
	return &managedIssuer{domain: domain, email: email, cache: autocert.DirCache(cache),
		client: newACMEClient(), renewBefore: 30 * 24 * time.Hour, order: make(chan struct{}, 1)}, nil
}

func (m *managedIssuer) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		path, body := m.tokenPath, m.tokenBody
		m.mu.RUnlock()
		if path == "" || r.URL.Path != path {
			fallback.ServeHTTP(w, r)
			return
		}
		w.Write([]byte(body))
	})
}

func (m *managedIssuer) certificate() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *managedIssuer) Certificate(ctx context.Context) (*tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cert := m.certificate()
	if cert == nil {
		data, err := m.cache.Get(ctx, m.domain)
		if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
			return nil, err
		}
		if err == nil {
			pair, parseErr := certificates.ParseTLSPair(data, data, m.domain)
			if parseErr == nil {
				cert = pair
				m.mu.Lock()
				m.current = cert
				m.mu.Unlock()
			}
		}
	}
	now := time.Now()
	if cert == nil || now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		var err error
		cert, err = m.obtain(ctx, cert)
		if err != nil {
			return nil, err
		}
	}
	if m.cancel == nil {
		var lifetime context.Context
		lifetime, m.cancel = context.WithCancel(context.Background())
		m.done = make(chan struct{})
		go m.renew(lifetime)
	}
	return cert, nil
}

func (m *managedIssuer) Close() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
}

func (m *managedIssuer) renew(ctx context.Context) {
	defer close(m.done)
	var retry time.Duration
	for {
		cert := m.certificate()
		delay := retry
		if delay == 0 {
			before := m.renewBefore
			// A short-lived certificate must not trigger another order as
			// soon as it is issued. Keep the configured window for longer leases.
			if lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore); before >= lifetime {
				before = lifetime / 3
			}
			jitter := min(before/10, time.Hour)
			delay = time.Until(cert.Leaf.NotAfter.Add(-before + randv2.N(max(jitter, time.Nanosecond))))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		_, err := m.obtain(ctx, cert)
		if ctx.Err() != nil {
			return
		}
		retry = 0
		if err != nil {
			retry = 30*time.Minute + randv2.N(30*time.Minute)
		}
	}
}

func (m *managedIssuer) obtain(ctx context.Context, previous *tls.Certificate) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	select {
	case m.order <- struct{}{}:
		defer func() { <-m.order }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if latest := m.certificate(); latest != previous {
		return latest, nil
	}
	if err := m.register(ctx); err != nil {
		return nil, err
	}
	var signer crypto.Signer
	if previous != nil {
		signer, _ = previous.PrivateKey.(crypto.Signer)
	}
	if signer == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	}
	chain, err := m.issue(ctx, signer)
	if err != nil {
		return nil, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	for _, der := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	pair, err := certificates.ParseTLSPair(data, data, m.domain)
	if err != nil {
		return nil, err
	}
	if err := m.cache.Put(ctx, m.domain, data); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.current = pair
	m.mu.Unlock()
	return pair, nil
}

func (m *managedIssuer) register(ctx context.Context) error {
	if m.client.KID != "" {
		return nil
	}
	if m.client.Key == nil {
		key, err := m.accountKey(ctx)
		if err != nil {
			return err
		}
		m.client.Key = key
	}
	account := &acme.Account{}
	if m.email != "" {
		account.Contact = []string{"mailto:" + m.email}
	}
	_, err := m.client.Register(ctx, account, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil
	}
	var problem *acme.Error
	if errors.As(err, &problem) && problem.StatusCode == http.StatusConflict {
		existing, err := m.client.GetReg(ctx, "")
		if err != nil {
			return err
		}
		m.client.KID = acme.KeyID(existing.URI)
		return nil
	}
	return err
}

func (m *managedIssuer) accountKey(ctx context.Context) (crypto.Signer, error) {
	const name = "acme_account+key"
	data, err := m.cache.Get(ctx, name)
	if errors.Is(err, autocert.ErrCacheMiss) {
		data, err = m.cache.Get(ctx, "acme_account.key")
	}
	if errors.Is(err, autocert.ErrCacheMiss) {
		key, createErr := m.createAccountKey(ctx, name)
		if !errors.Is(createErr, os.ErrExist) {
			return key, createErr
		}
		data, err = m.cache.Get(ctx, name)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block != nil {
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if signer, ok := key.(crypto.Signer); ok {
				return signer, nil
			}
		}
	}
	return nil, errors.New("invalid ACME account key")
}

func (m *managedIssuer) createAccountKey(ctx context.Context, name string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// Different domains using this account can start renewing together.
	// Publish a complete key without replacing another issuer's identity.
	tmp, err := os.CreateTemp(string(m.cache), ".account-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	writeErr := pem.Encode(tmp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, closeErr, ctx.Err()); err != nil {
		return nil, err
	}
	err = os.Link(tmp.Name(), filepath.Join(string(m.cache), name))
	return key, err
}

func (m *managedIssuer) issue(ctx context.Context, key crypto.Signer) ([][]byte, error) {
	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(m.domain))
	if err != nil {
		return nil, err
	}
	if order.Status == acme.StatusPending {
		if err := m.validateOrder(ctx, order); err != nil {
			return nil, err
		}
		order, err = m.client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, err
		}
	}
	if order.Status != acme.StatusReady {
		return nil, fmt.Errorf("unexpected ACME order status %q", order.Status)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.domain}}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	return chain, err
}

func (m *managedIssuer) validateOrder(ctx context.Context, order *acme.Order) error {
	for _, url := range order.AuthzURLs {
		auth, err := m.client.GetAuthorization(ctx, url)
		if err != nil {
			return err
		}
		if auth.Identifier.Type != "dns" || auth.Identifier.Value != m.domain {
			return fmt.Errorf("unexpected ACME identifier %q", auth.Identifier.Value)
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		if err := m.authorize(ctx, auth); err != nil {
			if ctx.Err() == nil {
				cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
				current, readErr := m.client.GetAuthorization(cleanup, url)
				if readErr == nil && current.Status == acme.StatusPending {
					_ = m.client.RevokeAuthorization(cleanup, url)
				}
				cancel()
			}
			return err
		}
	}
	return nil
}

func (m *managedIssuer) authorize(ctx context.Context, auth *acme.Authorization) error {
	for _, challenge := range auth.Challenges {
		if challenge.Type != "http-01" {
			continue
		}
		body, err := m.client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.tokenPath, m.tokenBody = m.client.HTTP01ChallengePath(challenge.Token), body
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			m.tokenPath, m.tokenBody = "", ""
			m.mu.Unlock()
		}()
		if _, err := m.client.Accept(ctx, challenge); err != nil {
			return err
		}
		_, err = m.client.WaitAuthorization(ctx, auth.URI)
		return err
	}
	return errors.New("ACME authority did not offer HTTP-01")
}
