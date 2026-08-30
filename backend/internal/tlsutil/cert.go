// Package tlsutil выпускает самоподписанный сертификат для веб-панели.
//
// Панель обязана работать по HTTPS с первой секунды: по ней передаётся пароль
// администратора. Публичного имени у роутера обычно нет, поэтому по умолчанию
// выпускается самоподписанный сертификат на все адреса машины, а желающие
// подставляют свой или получают Let's Encrypt.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureSelfSigned создаёт сертификат и ключ, если их ещё нет или срок истёк.
// Возвращает пути к файлам и отпечаток, который установщик показывает
// пользователю: по нему можно убедиться, что браузер соединился именно с
// роутером, а не с кем-то посередине.
func EnsureSelfSigned(dir, hostname string) (certPath, keyPath, fingerprint string, err error) {
	return EnsureSelfSignedForNames(dir, hostname)
}

// EnsureSelfSignedForNames additionally places public VPN endpoint names or
// addresses into the certificate SAN extension. Existing certificates are
// retained only while they cover every requested identity.
func EnsureSelfSignedForNames(dir, hostname string, names ...string) (certPath, keyPath, fingerprint string, err error) {
	certPath = filepath.Join(dir, "panel.crt")
	keyPath = filepath.Join(dir, "panel.key")

	identities := append([]string{hostname}, names...)
	if fp, ok := validExistingForNames(certPath, keyPath, identities); ok {
		return certPath, keyPath, fp, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"netOS"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		// Десять лет: роутер может годами стоять без обновлений, и протухший
		// сертификат панели — последнее, с чем стоит разбираться владельцу.
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostname, "localhost", hostname + ".lan"},
		IPAddresses:           localAddresses(),
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if name != "" {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", "", err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", "", err
	}
	return certPath, keyPath, Fingerprint(cert), nil
}

// Fingerprint возвращает отпечаток SHA-256 в привычном виде AA:BB:CC:...
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256Sum(cert.Raw)
	out := make([]byte, 0, len(sum)*3)
	const hexDigits = "0123456789ABCDEF"
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

func validExisting(certPath, keyPath string) (string, bool) {
	return validExistingForNames(certPath, keyPath, nil)
}

func validExistingForNames(certPath, keyPath string, names []string) (string, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "", false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", false
	}
	if time.Now().After(cert.NotAfter) {
		return "", false
	}
	for _, name := range names {
		if name != "" && cert.VerifyHostname(name) != nil {
			return "", false
		}
	}
	return Fingerprint(cert), true
}

// localAddresses собирает адреса машины, чтобы сертификат подходил при
// обращении по любому из них.
func localAddresses() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			ips = append(ips, v4)
		}
	}
	return ips
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	return nil
}
