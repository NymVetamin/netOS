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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/netos-router/netos/internal/system"
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

func validExistingForNames(certPath, keyPath string, names []string) (string, bool) {
	for _, path := range []string{certPath, keyPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		return "", false
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return "", false
	}
	fingerprint, err := ValidatePairForNames(certPath, keyPath, names...)
	return fingerprint, err == nil
}

// ValidatePairForNames performs a read-only validation of a netOS-managed TLS
// pair, including file type/mode, key match, validity window and every required
// DNS/IP identity.
func ValidatePairForNames(certPath, keyPath string, names ...string) (string, error) {
	for path, mode := range map[string]os.FileMode{certPath: 0o644, keyPath: 0o600} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("TLS-артефакт %s не является обычным файлом без symlink", path)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != mode {
			return "", fmt.Errorf("права TLS-артефакта %s: %04o, ожидалось %04o", path, info.Mode().Perm(), mode)
		}
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return "", fmt.Errorf("сертификат и ключ не образуют пару: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("сертификат не содержит PEM-блок")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", fmt.Errorf("сертификат вне срока действия")
	}
	for _, name := range names {
		if name != "" && cert.VerifyHostname(name) != nil {
			return "", fmt.Errorf("сертификат не покрывает имя %s", name)
		}
	}
	return Fingerprint(cert), nil
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
	return system.WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), perm)
}
