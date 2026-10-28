package api

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Only navigation is upgraded. Plaintext requests never reach the API or
// replay credentials through a method-preserving redirect.
func panelHTTPSRedirect(port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Use HTTPS", http.StatusMethodNotAllowed)
			return
		}
		authority, err := url.Parse("https://" + r.Host)
		if err != nil || authority.Host == "" || authority.User != nil || authority.Path != "" || authority.RawQuery != "" || authority.Fragment != "" || strings.ContainsAny(r.Host, "\\\r\n\t ") {
			http.Error(w, "Invalid Host", http.StatusBadRequest)
			return
		}
		host := authority.Hostname()
		if host == "" || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
			http.Error(w, "Invalid Host", http.StatusBadRequest)
			return
		}
		if port != 443 {
			host = net.JoinHostPort(host, strconv.Itoa(port))
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		target := &url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
}
