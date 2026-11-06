//go:build linux

package channels

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIntegrationOpenConnectP12(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		init, _ := os.Readlink("/proc/1/ns/" + kind)
		if self == init {
			t.Fatal("refusing host namespace", kind)
		}
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", name, err, out)
		}
		return string(out)
	}
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "sysfs", "sysfs", "/sys")
	root, err := os.MkdirTemp("/var/lib", "netos-p12-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ns := fmt.Sprintf("netos-p12-%d", os.Getpid())
	run("ip", "netns", "add", ns)
	defer exec.Command("ip", "netns", "del", ns).Run()
	remote := func(args ...string) string { return run("ip", append([]string{"netns", "exec", ns}, args...)...) }
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "p12host", "type", "veth", "peer", "name", "p12peer")
	run("ip", "link", "set", "p12peer", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "p12host")
	run("ip", "link", "set", "p12host", "up")
	remote("ip", "link", "set", "lo", "up")
	remote("ip", "addr", "add", "192.0.2.2/24", "dev", "p12peer")
	remote("ip", "link", "set", "p12peer", "up")
	cert, key := filepath.Join(root, "ca.crt"), filepath.Join(root, "ca.key")
	run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=p12-test", "-addext", "subjectAltName=IP:192.0.2.2", "-keyout", key, "-out", cert)
	clientKey, csr, clientCert := filepath.Join(root, "client.key"), filepath.Join(root, "client.csr"), filepath.Join(root, "client.crt")
	run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=client", "-keyout", clientKey, "-out", csr)
	run("openssl", "x509", "-req", "-in", csr, "-CA", cert, "-CAkey", key, "-CAcreateserial", "-days", "1", "-out", clientCert)
	p12 := filepath.Join(root, "client.p12")
	export := exec.Command("openssl", "pkcs12", "-export", "-in", clientCert, "-inkey", clientKey, "-certfile", cert, "-out", p12, "-passout", "stdin")
	export.Stdin = strings.NewReader("p12-test-password\n")
	if out, err := export.CombinedOutput(); err != nil {
		t.Fatalf("export: %s %v", out, err)
	}
	raw, err := os.ReadFile(p12)
	if err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(root, "passwd")
	passcmd := exec.Command("ocpasswd", "-c", passwd, "client")
	passcmd.Stdin = strings.NewReader("account-test-password\naccount-test-password\n")
	if out, err := passcmd.CombinedOutput(); err != nil {
		t.Fatalf("ocpasswd: %v %s", err, out)
	}
	serverConf := filepath.Join(root, "ocserv.conf")
	var server *exec.Cmd
	startServer := func(auth string) {
		t.Helper()
		if server != nil {
			syscall.Kill(-server.Process.Pid, syscall.SIGTERM)
			server.Wait()
		}
		text := fmt.Sprintf("auth = %s\ntcp-port = 4443\nudp-port = 4443\nlisten-host = 192.0.2.2\nrun-as-user = root\nrun-as-group = root\nsocket-file = %s/ocserv.sock\nserver-cert = %s\nserver-key = %s\nca-cert = %s\ncert-user-oid = 2.5.4.3\ndevice = vpnp12\nipv4-network = 10.253.99.0\nipv4-netmask = 255.255.255.0\nmax-clients = 8\nmax-same-clients = 4\nkeepalive = 30\ndpd = 30\ntry-mtu-discovery = false\nisolate-workers = false\n", auth, root, cert, key, cert)
		if err := os.WriteFile(serverConf, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		server = exec.Command("ip", "netns", "exec", ns, "ocserv", "-f", "-c", serverConf)
		server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		log, err := os.OpenFile(filepath.Join(root, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		server.Stdout = log
		server.Stderr = log
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		log.Close()
		time.Sleep(time.Second)
	}
	startServer(`"certificate"`)
	defer func() { syscall.Kill(-server.Process.Pid, syscall.SIGTERM); server.Wait() }()
	ch := config.Channel{ID: "p12-test", Index: 996, Name: "P12 test", Type: "openconnect", Enabled: true, Mode: "tun", Config: map[string]any{"server": "https://192.0.2.2:4443", "auth_mode": "certificate", "client_certificate": base64.StdEncoding.EncodeToString(raw), "certificate_password": "p12-test-password", "no_dtls": true}}
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	ch.Config["servercert"] = "pin-sha256:" + base64.StdEncoding.EncodeToString(fingerprint[:])

	s := New(system.NewExec(), filepath.Join(root, "state"))
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	_, _, script, unit := s.openConnectPaths(ch)
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatal("test unit exists")
	}
	dropin := unit + ".d"
	if _, err := os.Stat(dropin); !os.IsNotExist(err) {
		t.Fatal("test drop-in exists")
	}
	if err := os.MkdirAll(dropin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropin, "network.conf"), []byte(fmt.Sprintf("[Service]\nNetworkNamespacePath=/proc/%d/ns/net\n", os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		s.cleanupOpenConnect(context.Background(), ch)
		os.RemoveAll(dropin)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "reset-failed", openConnectUnitName(ch)).Run()
	}()
	apply := func(owned bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		_, err := s.applyOpenConnect(ctx, ch, owned, true)
		return err
	}
	ping := func() {
		t.Helper()
		run("ip", "route", "replace", "10.253.99.1/32", "dev", InterfaceName(ch))
		run("ping", "-c", "1", "-W", "2", "10.253.99.1")
	}
	if err := apply(false); err != nil {
		log, _ := os.ReadFile(filepath.Join(root, "server.log"))
		t.Fatalf("initial: %v server=%s", err, log)
	}
	info, err := os.Stat(openConnectCertificatePath(script))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("P12 file permissions", err)
	}
	ping()
	pid := run("systemctl", "show", "-p", "MainPID", "--value", openConnectUnitName(ch))
	if err := apply(true); err != nil {
		t.Fatal(err)
	}
	ping()
	if pid != run("systemctl", "show", "-p", "MainPID", "--value", openConnectUnitName(ch)) {
		t.Fatal("unchanged apply restarted client")
	}
	ch.Config["certificate_password"] = "wrong-password"
	if err := apply(true); err == nil {
		t.Fatal("wrong password accepted")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !s.openConnectReady(context.Background(), InterfaceName(ch)) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	ping() // The failed update must restore service before any retry.
	ch.Config["certificate_password"] = "p12-test-password"
	if err := apply(true); err != nil {
		t.Fatal("retry", err)
	}
	ping()
	ch.Config["auth_mode"] = "both"
	ch.Config["username"] = "client"
	ch.Config["password"] = "account-test-password"
	startServer(`"certificate"` + "\nauth = \"plain[passwd=" + passwd + "]\"")
	if err := apply(true); err != nil {
		t.Fatal("both", err)
	}
	ping()
	ch.Config["auth_mode"] = "password"
	startServer(`"plain[passwd=` + passwd + `]"`)
	if err := apply(true); err != nil {
		t.Fatal("password", err)
	}
	ping()
	if _, err := os.Stat(openConnectCertificatePath(script)); !os.IsNotExist(err) {
		t.Fatal("certificate survived password mode")
	}
	t.Log("P12 certificate/repeat/no restart/wrong password rollback/retry/both/password and ping passed")
}
