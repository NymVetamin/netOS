package vpnservers

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/netos-router/netos/internal/config"
	"golang.org/x/crypto/md4"
)

const ikev2AuthUnit = "netos-ikev2-auth.service"
const ikev2AuthDictionary = "$INCLUDE /usr/share/freeradius/dictionary.cisco.vpn3000\n"

// MSCHAPv2 requires an NT password hash. Emitting the binary hash also keeps
// arbitrary passwords out of FreeRADIUS's configuration expansion syntax.
func ikev2NTPassword(password string) string {
	h := md4.New()
	for _, u := range utf16.Encode([]rune(password)) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], u)
		_, _ = h.Write(b[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readIKEv2AuthSecret(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "radius.secret"))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(b))
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("некорректный внутренний ключ авторизации IKEv2")
	}
	return secret, nil
}

func ensureIKEv2AuthSecret(root string) (string, error) {
	secret, err := readIKEv2AuthSecret(root)
	if err == nil || !os.IsNotExist(err) {
		return secret, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret = hex.EncodeToString(b)
	return secret, writeFile(filepath.Join(root, "radius.secret"), []byte(secret+"\n"), 0o600)
}

func renderIKEv2AuthUsers(servers []config.VPNServer) ([]byte, error) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, server := range servers {
		ike, err := server.IKEv2Config()
		if err != nil {
			return nil, err
		}
		var splitRoutes string
		dnsServers := server.ClientDNS(ike.UseRouterDNS, ike.DNS)
		for _, peer := range server.Peers {
			if !peer.Enabled {
				continue
			}
			user := peer.Credentials["username"]
			if user == "" || strings.ContainsAny(user, "\"\\\r\n\t ") || seen[user] {
				return nil, fmt.Errorf("некорректный или повторный логин IKEv2")
			}
			seen[user] = true
			ip, err := netip.ParseAddr(peer.Address)
			if err != nil || !ip.Is4() {
				return nil, fmt.Errorf("некорректный адрес клиента IKEv2")
			}
			fmt.Fprintf(&b, "\"%s\" NT-Password := 0x%s\n", user, ikev2NTPassword(peer.Credentials["password"]))
			fmt.Fprintf(&b, "    Framed-IP-Address = %s,\n    Class = \"netos-srv%d\"", ip, server.Index)
			for i, dns := range dnsServers {
				address, err := netip.ParseAddr(dns)
				if err != nil || !address.Is4() {
					return nil, fmt.Errorf("некорректный DNS IKEv2")
				}
				attribute := "MS-Primary-DNS-Server"
				if i > 0 {
					attribute = "MS-Secondary-DNS-Server"
				}
				fmt.Fprintf(&b, ",\n    %s += %s", attribute, address)
			}
			if len(ike.SplitRoutes) > 0 {
				if splitRoutes == "" {
					splitRoutes = strings.Join(ikev2RoutesWithDNS(ike.SplitRoutes, dnsServers), ",")
				}
				fmt.Fprintf(&b, ",\n    CVPN3000-IPSec-Split-Tunneling-Policy = 1,\n    CVPN3000-IPSec-Split-Tunnel-List = \"%s\"", splitRoutes)
			}
			fmt.Fprintln(&b)
		}
	}
	return []byte(b.String()), nil
}

func renderIKEv2AuthConfig(root, secret string) []byte {
	return []byte(fmt.Sprintf(`prefix = /usr
localstatedir = /var
libdir = /usr/lib/freeradius
name = netos-ikev2-auth
logdir = /run/netos-ikev2-auth
radacctdir = /run/netos-ikev2-auth
pidfile = /run/netos-ikev2-auth/radius.pid
proxy_requests = no
log {
 destination = stdout
 auth = no
}
client netos {
 ipaddr = 127.0.0.1
 secret = %s
 require_message_authenticator = yes
}
modules {
 files {
  filename = %s
 }
 mschap {
 }
 eap {
  default_eap_type = mschapv2
  mschapv2 {
  }
 }
}
server netos {
 listen {
  type = auth
  ipaddr = 127.0.0.1
  port = %d
 }
 authorize {
  files
  eap
 }
 authenticate {
  Auth-Type EAP {
   eap
  }
  Auth-Type MS-CHAP {
   mschap
  }
 }
}
`, secret, filepath.ToSlash(filepath.Join(root, "users")), config.IKEv2AuthPort))
}

func renderIKEv2AuthUnit(root string) []byte {
	return []byte(`[Unit]
Description=netOS: IKEv2 user authentication
Before=netos-strongswan.service

[Service]
Type=notify
NotifyAccess=all
ExecStartPre=/usr/sbin/freeradius -C -lstdout -d ` + root + `
ExecStart=/usr/sbin/freeradius -f -d ` + root + `
Restart=on-failure
RestartSec=2
RuntimeDirectory=netos-ikev2-auth
RuntimeDirectoryMode=0700
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
NoNewPrivileges=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_UNIX

[Install]
WantedBy=multi-user.target
`)
}
