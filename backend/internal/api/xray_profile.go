package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type xrayProfile struct {
	Link   string         `json:"link"`
	Config map[string]any `json:"config"`
}

// The same outbound is exported as JSON and encoded in a protocol-specific URI.
// Secrets are read on an explicit authorized request, not from redacted UI state.
func xrayClientProfile(server config.VPNServer, peer config.VPNPeer, pin string) (xrayProfile, error) {
	xr, err := server.XrayConfig()
	if err != nil {
		return xrayProfile{}, err
	}
	host, portText, err := net.SplitHostPort(xr.PublicEndpoint)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host == "" || port < 1 || port > 65535 || strings.ContainsAny(host, "/?#@ \t\r\n") {
		return xrayProfile{}, fmt.Errorf("Укажите адрес подключения в формате host:port")
	}
	protocol := xr.Protocol
	if protocol == "" {
		protocol = "reality"
	}
	settings := map[string]any{"address": host, "port": port}
	outbound := map[string]any{"protocol": protocol, "settings": settings}
	q := url.Values{}
	u := url.URL{Scheme: protocol, Host: net.JoinHostPort(host, portText), Fragment: peer.Name}
	if u.Fragment == "" {
		u.Fragment = peer.ID
	}
	secret := peer.Credentials["password"]
	if protocol == "vless" || protocol == "vmess" || protocol == "reality" {
		secret = peer.Credentials["uuid"]
	}
	if secret == "" {
		return xrayProfile{}, fmt.Errorf("Не заданы учётные данные клиента")
	}
	u.User = url.User(secret)
	switch protocol {
	case "reality":
		link, err := realityClientLink(server, peer)
		if err != nil {
			return xrayProfile{}, err
		}
		parsed, _ := url.Parse(link)
		v := parsed.Query()
		outbound["protocol"] = "vless"
		settings["id"], settings["encryption"], settings["flow"] = secret, "none", xr.Flow
		outbound["tag"] = "proxy"
		outbound["streamSettings"] = map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": v.Get("sni"), "fingerprint": v.Get("fp"), "password": v.Get("pbk"), "shortId": v.Get("sid")}}
		u = *parsed
	case "vless":
		settings["id"], settings["encryption"] = secret, "none"
		q.Set("encryption", "none")
	case "vmess":
		settings["id"], settings["security"] = secret, "auto"
	case "trojan":
		settings["password"] = secret
	case "shadowsocks":
		method := xr.Method
		if method == "" {
			method = "aes-256-gcm"
		}
		settings["method"], settings["password"] = method, secret
		u.Scheme = "ss"
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(method + ":" + secret)))
	case "hysteria":
		settings["version"] = 2
		u.Scheme, u.Path = "hysteria2", "/"
	case "socks", "http":
		username := peer.Credentials["username"]
		if username == "" {
			return xrayProfile{}, fmt.Errorf("Не задан логин клиента")
		}
		if protocol == "http" && strings.Contains(username, ":") {
			return xrayProfile{}, fmt.Errorf("Логин HTTP-прокси не может содержать двоеточие")
		}
		outbound["settings"] = map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "users": []any{map[string]any{"user": username, "pass": secret}}}}}
		u.User = url.UserPassword(username, secret)
		if protocol == "socks" {
			u.Scheme = "socks5"
		}
	default:
		return xrayProfile{}, fmt.Errorf("Для этого протокола используйте профиль WireGuard")
	}
	if xr.UsesTLS() {
		tls := map[string]any{"serverName": host}
		q.Set("sni", host)
		if pin != "" {
			tls["pinnedPeerCertSha256"] = pin
			if protocol == "hysteria" {
				q.Set("pinSHA256", pin)
				// Hysteria's URI uses insecure + an explicit pin for private CAs.
				q.Set("insecure", "1")
			} else {
				q.Set("pcs", pin)
			}
		}
		stream := map[string]any{"network": "tcp", "security": "tls", "tlsSettings": tls}
		if protocol == "hysteria" {
			delete(stream, "network")
			stream["method"] = "hysteria"
			stream["hysteriaSettings"] = map[string]any{"version": 2, "auth": secret}
		} else {
			q.Set("security", "tls")
			q.Set("type", "tcp")
			if peer.TLSFingerprint != "" {
				tls["fingerprint"] = peer.TLSFingerprint
				q.Set("fp", peer.TLSFingerprint)
			}
		}
		outbound["streamSettings"] = stream
	}
	if protocol != "reality" {
		u.RawQuery = q.Encode()
	}
	link := u.String()
	if protocol == "vmess" {
		body, _ := json.Marshal(map[string]string{"v": "2", "ps": u.Fragment, "add": host, "port": portText, "id": secret, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": ""})
		link = "vmess://" + base64.StdEncoding.EncodeToString(body)
	}
	inbound := map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": protocol == "reality"}}
	if protocol == "reality" {
		inbound["tag"] = "socks"
	}
	return xrayProfile{Link: link, Config: map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{inbound}, "outbounds": []any{outbound}}}, nil
}

func xrayProfilePin(cfg *config.Config, server config.VPNServer) (string, error) {
	xr, err := server.XrayConfig()
	if err != nil || !xr.UsesTLS() {
		return "", err
	}
	// Public ACME certificates renew automatically. Pinning a leaf would break
	// all issued profiles at renewal; use normal CA/name verification instead.
	if xr.TLS != nil && (xr.TLS.Mode == "acme" || (xr.TLS.Mode == "panel" && cfg.System.Panel.TLS.Mode == "acme")) {
		return "", nil
	}
	var data []byte
	if xr.TLS != nil && xr.TLS.Mode == "custom" {
		data = []byte(xr.TLS.CertPEM)
	} else {
		data, err = os.ReadFile(filepath.Join(vpnGeneratedDir, fmt.Sprintf("xray-srv%d-tls", server.Index), "panel.crt"))
		if err != nil {
			return "", fmt.Errorf("Сначала примените настройки сервера: сертификат ещё не выпущен")
		}
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("Не удалось прочитать сертификат сервера")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Некорректный сертификат сервера")
	}
	host, _, _ := net.SplitHostPort(xr.PublicEndpoint)
	if err := cert.VerifyHostname(host); err != nil {
		return "", fmt.Errorf("Сертификат не соответствует адресу подключения; примените настройки сервера")
	}
	if now := time.Now(); now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", fmt.Errorf("Срок действия сертификата истёк или ещё не начался")
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Server) handleXrayClientProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !may(r, "vpn-servers", true) {
		writeError(w, http.StatusForbidden, "Доступно только администратору")
		return
	}
	cfg := s.requestConfig(r)
	for _, server := range cfg.VPNServers {
		if server.ID != r.PathValue("id") || server.Type != "xray" {
			continue
		}
		for _, peer := range server.Peers {
			if peer.ID != r.PathValue("peer") {
				continue
			}
			pin, err := xrayProfilePin(cfg, server)
			if err != nil {
				writeError(w, http.StatusConflict, "%s", err)
				return
			}
			profile, err := xrayClientProfile(server, peer, pin)
			if err != nil {
				writeError(w, http.StatusConflict, "%s", err)
				return
			}
			writeJSON(w, http.StatusOK, profile)
			return
		}
	}
	writeError(w, http.StatusNotFound, "Клиент Xray не найден")
}
