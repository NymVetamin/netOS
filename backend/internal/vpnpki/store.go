// Package vpnpki keeps client identities and irreversible revocations outside
// configuration history and generated-file rollback snapshots.
package vpnpki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Client struct {
	Serial      string    `json:"serial"`
	Expires     time.Time `json:"expires"`
	Revoked     bool      `json:"revoked"`
	Certificate []byte    `json:"certificate"`
	Key         []byte    `json:"key"`
	Password    string    `json:"password"`
	P12         []byte    `json:"p12"`
}

var ErrNotIssued = errors.New("сертификат ещё не выпущен; примените настройки")

type revocation struct {
	Serial string
	At     time.Time
}
type state struct {
	ServerID    string
	CA          []byte
	Key         []byte
	Clients     map[string]Client
	Revocations []revocation
	CRLNumber   int64
}
type Store struct {
	Root   string
	Runner system.Runner
	mu     sync.Mutex
}

func New(root string, runner system.Runner) *Store { return &Store{Root: root, Runner: runner} }
func (s *Store) Dir(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.Root, "ocserv-"+hex.EncodeToString(sum[:16]))
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }

func (s *Store) load(id string, create bool) (*state, error) {
	file := filepath.Join(s.Dir(id), "state.json")
	for _, dir := range []string{s.Root, s.Dir(id)} {
		if info, err := os.Lstat(dir); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("небезопасный каталог PKI")
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if info, err := os.Lstat(file); err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
			return nil, fmt.Errorf("небезопасный файл PKI")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err == nil {
		var st state
		if err := json.Unmarshal(data, &st); err != nil {
			return nil, fmt.Errorf("повреждено хранилище сертификатов")
		}
		if st.ServerID != id || st.Clients == nil {
			return nil, fmt.Errorf("неверная идентичность хранилища сертификатов")
		}
		if _, _, err := st.signer(); err != nil {
			return nil, err
		}
		return &st, nil
	}
	if !os.IsNotExist(err) || !create {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "netOS OpenConnect " + id}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	st := &state{ServerID: id, CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), Clients: map[string]Client{}}
	if err := s.save(st); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *state) signer() (*x509.Certificate, crypto.Signer, error) {
	certBlock, _ := pem.Decode(st.CA)
	keyBlock, _ := pem.Decode(st.Key)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("повреждён центр сертификации")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("неподдерживаемый ключ CA")
	}
	a, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	b, _ := x509.MarshalPKIXPublicKey(signer.Public())
	if string(a) != string(b) {
		return nil, nil, fmt.Errorf("ключ CA не соответствует сертификату")
	}
	return cert, signer, nil
}

func (s *Store) save(st *state) error {
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Root, 0o700); err != nil {
		return err
	}
	dir := s.Dir(st.ServerID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(filepath.Join(dir, "state.json"), data, 0o600)
}

func (s *Store) issue(ctx context.Context, st *state, server config.VPNServer, peer config.VPNPeer) (Client, error) {
	ca, signer, err := st.signer()
	if err != nil {
		return Client{}, err
	}
	if time.Until(ca.NotAfter) < 48*time.Hour {
		return Client{}, fmt.Errorf("истекает срок центра сертификации")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Client{}, err
	}
	n, err := serial()
	if err != nil {
		return Client{}, err
	}
	now := time.Now().UTC()
	expires := now.AddDate(1, 0, 0)
	if expires.After(ca.NotAfter) {
		expires = ca.NotAfter
	}
	tpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: server.OcservUsername(peer)}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, signer)
	if err != nil {
		return Client{}, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Client{}, err
	}
	password := make([]byte, 18)
	if _, err := rand.Read(password); err != nil {
		return Client{}, err
	}
	client := Client{Serial: n.String(), Expires: expires, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), Password: base64.RawURLEncoding.EncodeToString(password)}
	dir, err := os.MkdirTemp(s.Dir(st.ServerID), "issue-")
	if err != nil {
		return Client{}, err
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{"client.crt": client.Certificate, "client.key": client.Key, "ca.crt": st.CA} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return Client{}, err
		}
	}
	_, err = s.Runner.RunInput(ctx, client.Password+"\n", "openssl", "pkcs12", "-export", "-in", filepath.Join(dir, "client.crt"), "-inkey", filepath.Join(dir, "client.key"), "-certfile", filepath.Join(dir, "ca.crt"), "-name", server.OcservUsername(peer), "-passout", "stdin", "-out", filepath.Join(dir, "client.p12"))
	if err != nil {
		return Client{}, fmt.Errorf("не удалось создать защищённый PKCS#12")
	}
	client.P12, err = os.ReadFile(filepath.Join(dir, "client.p12"))
	if err != nil {
		return Client{}, err
	}
	return client, nil
}

func revoke(st *state, id string) {
	client, ok := st.Clients[id]
	if !ok || client.Revoked {
		return
	}
	client.Revoked = true
	st.Clients[id] = client
	st.Revocations = append(st.Revocations, revocation{client.Serial, time.Now().UTC()})
}

func (s *Store) publish(st *state, server config.VPNServer) error {
	ca, key, err := st.signer()
	if err != nil {
		return err
	}
	var entries []x509.RevocationListEntry
	for _, rev := range st.Revocations {
		n, ok := new(big.Int).SetString(rev.Serial, 10)
		if !ok {
			return fmt.Errorf("повреждён реестр отзывов")
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: rev.At})
	}
	st.CRLNumber++
	// Persist revocations before publishing any runtime view. History rollback
	// never touches this file and cannot undo a revoked serial.
	if err := s.save(st); err != nil {
		return err
	}
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(st.CRLNumber), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.AddDate(0, 0, 7), RevokedCertificateEntries: entries}, ca, key)
	if err != nil {
		return err
	}
	dir := s.Dir(st.ServerID)
	if err := system.WriteFileAtomic(filepath.Join(dir, "ca.crt"), st.CA, 0o644); err != nil {
		return err
	}
	if err := system.WriteFileAtomic(filepath.Join(dir, "revoked.crl"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644); err != nil {
		return err
	}
	var allowed []string
	var oc *config.OcservServerConfig
	if server.Enabled && server.OcservAuthMode() != "password" {
		for _, peer := range server.Peers {
			client, ok := st.Clients[peer.ID]
			if peer.Enabled && ok && !client.Revoked && time.Now().Before(client.Expires) {
				if oc == nil {
					decoded, _ := server.OcservConfig()
					oc = &decoded
				}
				allowed = append(allowed, oc.Username(peer))
			}
		}
	}
	sort.Strings(allowed)
	return system.WriteFileAtomic(filepath.Join(dir, "allowed"), []byte(strings.Join(allowed, "\n")+"\n"), 0o600)
}

func (s *Store) Sync(ctx context.Context, server config.VPNServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	create := server.Enabled && server.OcservAuthMode() != "password"
	st, err := s.load(server.ID, create)
	if os.IsNotExist(err) && !create {
		return nil
	}
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, peer := range server.Peers {
		wanted[peer.ID] = true
		if _, ok := st.Clients[peer.ID]; !ok && create {
			client, err := s.issue(ctx, st, server, peer)
			if err != nil {
				return err
			}
			st.Clients[peer.ID] = client
		}
	}
	for id := range st.Clients {
		if !wanted[id] {
			revoke(st, id)
		}
	}
	return s.publish(st, server)
}

// Reconcile also visits removed servers: deletion permanently revokes their
// identities, while disabling a server only empties the runtime allowlist.
func (s *Store) Reconcile(ctx context.Context, cfg *config.Config) error {
	wanted := map[string]bool{}
	for _, server := range cfg.VPNServers {
		if server.Type != "ocserv" {
			continue
		}
		wanted[server.ID] = true
		if err := s.Sync(ctx, server); err != nil {
			return fmt.Errorf("сертификаты OpenConnect: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.Root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "ocserv-") {
			continue
		}
		if !entry.IsDir() {
			return fmt.Errorf("небезопасный каталог PKI")
		}
		data, err := os.ReadFile(filepath.Join(s.Root, entry.Name(), "state.json"))
		if err != nil {
			return err
		}
		var identity struct{ ServerID string }
		if err := json.Unmarshal(data, &identity); err != nil {
			return err
		}
		if wanted[identity.ServerID] {
			continue
		}
		if filepath.Base(s.Dir(identity.ServerID)) != entry.Name() {
			return fmt.Errorf("неверный каталог PKI")
		}
		st, err := s.load(identity.ServerID, false)
		if err != nil {
			return err
		}
		for id := range st.Clients {
			revoke(st, id)
		}
		if err := s.publish(st, config.VPNServer{ID: st.ServerID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Get(serverID, peerID string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(serverID, false)
	if err != nil {
		return Client{}, err
	}
	client, ok := st.Clients[peerID]
	if !ok {
		return Client{}, ErrNotIssued
	}
	return client, nil
}

// ClientStatus deliberately excludes all certificate material and secrets.
type ClientStatus struct {
	Serial  string    `json:"serial"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked"`
}

func (s *Store) Statuses(serverID string) (map[string]ClientStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(serverID, false)
	if err != nil {
		return nil, err
	}
	result := make(map[string]ClientStatus, len(st.Clients))
	for id, client := range st.Clients {
		result[id] = ClientStatus{Serial: client.Serial, Expires: client.Expires, Revoked: client.Revoked}
	}
	return result, nil
}

func (s *Store) Revoke(server config.VPNServer, peerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(server.ID, false)
	if err != nil {
		return err
	}
	if _, ok := st.Clients[peerID]; !ok {
		return fmt.Errorf("сертификат не найден")
	}
	revoke(st, peerID)
	return s.publish(st, server)
}

func (s *Store) Reissue(ctx context.Context, server config.VPNServer, peer config.VPNPeer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(server.ID, true)
	if err != nil {
		return err
	}
	client, err := s.issue(ctx, st, server, peer)
	if err != nil {
		return err
	}
	revoke(st, peer.ID)
	st.Clients[peer.ID] = client
	return s.publish(st, server)
}
