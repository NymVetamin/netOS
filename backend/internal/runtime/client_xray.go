package runtime

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
)

const xrayDNSWindow = 10 * time.Second
const xrayJoinDelay = 2 * time.Second

var xrayDNSLine = regexp.MustCompile(`(?:got answer:|cache HIT:|cache OPTIMISTE:)\s+(\S+)\s+->\s+\[([^\]]*)\]`)
var xrayAccessLine = regexp.MustCompile(`\baccepted\s+(?:tcp|udp):(\S+)\s+\[([^\]]+)\].*\bemail:\s+(\S+)\s*$`)

type xrayDNSKey struct{ process, ip string }
type xrayPending struct {
	process, client, ip string
	at                  time.Time
}
type xrayResource struct {
	client, domain, source string
	at                     time.Time
}

// The join is intentionally approximate, bounded and scoped to one Xray process.
// Multiple candidate domains never become a guessed client/domain association.
type xrayResources struct {
	cfg         *config.Config
	users       map[string]string
	answers     map[xrayDNSKey]map[string]time.Time
	answerCount int
	units       map[string]bool
	pending     []xrayPending
	unsafeUntil time.Time
	limited     bool
}

func (x *xrayResources) configure(cfg *config.Config) {
	if x.cfg == cfg {
		return
	}
	x.cfg = cfg
	x.users = map[string]string{}
	x.answers = map[xrayDNSKey]map[string]time.Time{}
	x.answerCount = 0
	x.units = map[string]bool{}
	x.pending = nil
	x.unsafeUntil = time.Time{}
	if cfg == nil || !cfg.TrafficMonitor.Enabled {
		return
	}
	for _, server := range cfg.VPNServers {
		if !server.Enabled || server.Type != "xray" {
			continue
		}
		unit := fmt.Sprintf("netos-xray-srv%d.service", server.Index)
		x.units[unit] = true
		for _, peer := range server.Peers {
			if peer.Enabled {
				x.users[unit+"|"+server.ID+"/"+peer.ID] = "vpn:" + server.ID + ":" + peer.ID
			}
		}
	}
}

func resourceDomain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/|[]") {
		return ""
	}
	return s
}

func (x *xrayResources) consume(at time.Time, unit, process, line string) []xrayResource {
	if process == "" || !x.units[unit] || x.cfg == nil || !x.cfg.TrafficMonitor.Enabled {
		return nil
	}
	process = unit + "|" + process
	if m := xrayDNSLine.FindStringSubmatch(line); len(m) == 3 {
		domain := resourceDomain(m[1])
		if domain == "" {
			return nil
		}
		for _, value := range strings.FieldsFunc(m[2], func(r rune) bool { return r == ',' || r == ' ' }) {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			key := xrayDNSKey{process, ip.Unmap().String()}
			if _, exists := x.answers[key][domain]; !exists && x.answerCount >= 4096 {
				x.limited = true
				x.unsafeUntil = at.Add(xrayDNSWindow + xrayJoinDelay)
				continue
			}
			if x.answers[key] == nil {
				x.answers[key] = map[string]time.Time{}
			}
			if _, exists := x.answers[key][domain]; !exists {
				x.answerCount++
			}
			x.answers[key][domain] = at
		}
		return nil
	}
	m := xrayAccessLine.FindStringSubmatch(line)
	if len(m) != 4 {
		return nil
	}
	client := x.users[unit+"|"+m[3]]
	if client == "" {
		return nil
	}
	// Count the generated outgoing routes, not blocked/API/internal connections.
	route := strings.Fields(strings.ReplaceAll(m[2], ">", " "))
	if len(route) == 0 {
		return nil
	}
	outbound := route[len(route)-1]
	if !strings.EqualFold(outbound, "direct") && !strings.HasPrefix(outbound, "channel-") {
		return nil
	}
	host, _, err := net.SplitHostPort(m[1])
	if err != nil {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if len(x.pending) >= 2048 {
			x.limited = true
			return []xrayResource{{client, ip.Unmap().String(), "xray-ip", at}}
		}
		x.pending = append(x.pending, xrayPending{process, client, ip.Unmap().String(), at})
		return nil
	}
	if domain := resourceDomain(host); domain != "" {
		return []xrayResource{{client, domain, "xray-domain", at}}
	}
	return nil
}

func (x *xrayResources) flush(now time.Time) []xrayResource {
	var result []xrayResource
	keep := x.pending[:0]
	for _, p := range x.pending {
		if now.Before(p.at.Add(xrayJoinDelay)) {
			keep = append(keep, p)
			continue
		}
		domain := ""
		if !p.at.Before(x.unsafeUntil) {
			for candidate, at := range x.answers[xrayDNSKey{p.process, p.ip}] {
				if at.Before(p.at.Add(-xrayDNSWindow)) || at.After(p.at.Add(xrayJoinDelay)) {
					continue
				}
				if domain != "" && domain != candidate {
					domain = ""
					break
				}
				domain = candidate
			}
		}
		if domain == "" {
			result = append(result, xrayResource{p.client, p.ip, "xray-ip", p.at})
		} else {
			result = append(result, xrayResource{p.client, domain, "xray-dns", p.at})
		}
	}
	x.pending = keep
	for key, domains := range x.answers {
		for domain, at := range domains {
			if at.Before(now.Add(-xrayDNSWindow - xrayJoinDelay)) {
				delete(domains, domain)
				x.answerCount--
			}
		}
		if len(domains) == 0 {
			delete(x.answers, key)
		}
	}
	return result
}

func (h *ClientHistory) addXrayResources(events []xrayResource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.enabled {
		return
	}
	for _, e := range events {
		key := e.client + "|" + e.domain + "|" + e.source
		if h.resources == nil {
			h.resources = map[string]*DNSCount{}
		}
		d := h.resources[key]
		if d == nil {
			if len(h.resources) >= 4096 {
				h.limited = true
				continue
			}
			d = &DNSCount{Client: e.client, Domain: e.domain, Source: e.source, First: e.at.Unix()}
			h.resources[key] = d
		}
		d.Count++
		d.Last = e.at.Unix()
	}
}
