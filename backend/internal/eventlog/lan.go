package eventlog

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Names resolves identifiers to what the administrator calls them; any field
// may be nil. Callers read the applied configuration.
type Names struct {
	Client func(mac string) string   // clients from the configuration
	SSID   func(iface string) string // Wi-Fi network served by a hostapd interface
}

func (n *Names) client(mac, hostname string) string {
	name := ""
	if n != nil && n.Client != nil {
		name = n.Client(mac)
	}
	if name == "" {
		name = hostname
	}
	if name == "" {
		return mac
	}
	return name + " (" + mac + ")"
}

// LAN turns hostapd and DHCP server messages into Wi-Fi and DHCP events. It
// is shared by the journal follower and the dns.log reader (dnsmasq writes
// DHCP there while the query log is enabled), hence the mutex.
type LAN struct {
	Log   *Log
	Names *Names
	mu    sync.Mutex
	// leases suppresses renewals: a client re-acknowledged the address it
	// already had is not news. reasons/mismatch join hostapd's neighbouring
	// lines. All three are bounded by lanStateLimit.
	leases   map[string]lease
	reasons  map[string]wifiNote
	mismatch map[string]time.Time
}

type lease struct{ ip, host string }

type wifiNote struct {
	text string
	at   time.Time
}

// ponytail: a full map is dropped rather than aged entry by entry; the cost
// is one repeated "got address" or a missing disconnect reason.
const lanStateLimit = 4096

const mac = `([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`

var (
	hostapdLine   = regexp.MustCompile(`^(\S+): (AP-STA-CONNECTED|AP-STA-DISCONNECTED|AP-STA-POSSIBLE-PSK-MISMATCH) ` + mac)
	hostapdReason = regexp.MustCompile(`^\S+: STA ` + mac + ` IEEE 802\.11: (deauthenticated|disassociated)(?: due to (.+))?$`)

	dnsmasqDHCP   = regexp.MustCompile(`\b(DHCPACK|DHCPRELEASE|DHCPNAK)\(([^)]+)\) (\S+) ` + mac + `(?: (.+))?`)
	dnsmasqNoFree = regexp.MustCompile(`\bDHCPDISCOVER\(([^)]+)\) ` + mac + ` no address available`)
	iscAck        = regexp.MustCompile(`^DHCP(ACK|NAK) on (\S+) to ` + mac + `(?: \(([^)]*)\))? via (\S+)`)
	iscRelease    = regexp.MustCompile(`^DHCPRELEASE of (\S+) from ` + mac + `(?: \(([^)]*)\))? via (\S+)`)
	iscNoFree     = regexp.MustCompile(`^DHCPDISCOVER from ` + mac + `.* via (\S+): .*no free leases`)
	keaAlloc      = regexp.MustCompile(`\bDHCP4_LEASE_ALLOC \[hwtype=1 ` + mac + `\].*lease (\S+) has been allocated`)
	keaRelease    = regexp.MustCompile(`\bDHCP4_RELEASE \[hwtype=1 ` + mac + `\].*address (\S+) was released`)
	keaNoFree     = regexp.MustCompile(`\bALLOC_ENGINE_V4_ALLOC_FAIL\S* \[hwtype=1 ` + mac + `\]`)
)

var wifiReasons = map[string]string{
	"inactivity (timer DEAUTH/REMOVE)": "долго не отвечал",
	"inactivity":                       "долго не отвечал",
	"local deauth request":             "отключён точкой доступа",
}

// WiFi handles one hostapd output line.
func (l *LAN) WiFi(at time.Time, line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if m := hostapdReason.FindStringSubmatch(line); m != nil {
		if l.reasons == nil || len(l.reasons) >= lanStateLimit {
			l.reasons = map[string]wifiNote{}
		}
		l.reasons[strings.ToLower(m[1])] = wifiNote{wifiReasons[m[3]], at}
		return
	}
	m := hostapdLine.FindStringSubmatch(line)
	if m == nil {
		return
	}
	iface, event, addr := m[1], m[2], strings.ToLower(m[3])
	source := iface
	if l.Names != nil && l.Names.SSID != nil {
		if ssid := l.Names.SSID(iface); ssid != "" {
			source = ssid
		}
	}
	who := l.Names.client(addr, "")
	switch event {
	case "AP-STA-CONNECTED":
		l.Log.Add(at, WiFi, Info, source, who+" подключился")
	case "AP-STA-DISCONNECTED":
		msg := who + " отключился"
		if note, ok := l.reasons[addr]; ok && at.Sub(note.at) < 3*time.Second && note.text != "" {
			msg += ": " + note.text
		}
		delete(l.reasons, addr)
		l.Log.Add(at, WiFi, Info, source, msg)
	case "AP-STA-POSSIBLE-PSK-MISMATCH":
		// hostapd reports every retry of the handshake; one attempt is one event.
		if last, ok := l.mismatch[addr]; ok && at.Sub(last) < 30*time.Second {
			return
		}
		if l.mismatch == nil || len(l.mismatch) >= lanStateLimit {
			l.mismatch = map[string]time.Time{}
		}
		l.mismatch[addr] = at
		l.Log.Add(at, WiFi, Warning, source, who+": неверный пароль Wi-Fi")
	}
}

// DHCP handles one line of dnsmasq, ISC dhcpd or Kea.
func (l *LAN) DHCP(at time.Time, line string) {
	// Every pattern below needs one of these words. dnsmasq writes its DNS
	// traffic to the same stream (dns.log, or journald while the traffic
	// monitor is on), several lines per query: they stop here.
	if !strings.Contains(line, "DHCP") && !strings.Contains(line, "ALLOC_ENGINE") {
		return
	}
	kind, iface, ip, addr, host := "", "", "", "", ""
	if m := dnsmasqDHCP.FindStringSubmatch(line); m != nil {
		kind, iface, ip, addr, host = m[1], m[2], m[3], m[4], m[5]
	} else if m := dnsmasqNoFree.FindStringSubmatch(line); m != nil {
		kind, iface, addr = "NOFREE", m[1], m[2]
	} else if m := iscAck.FindStringSubmatch(line); m != nil {
		kind, ip, addr, host, iface = "DHCP"+m[1], m[2], m[3], m[4], m[5]
	} else if m := iscRelease.FindStringSubmatch(line); m != nil {
		kind, ip, addr, host, iface = "DHCPRELEASE", m[1], m[2], m[3], m[4]
	} else if m := iscNoFree.FindStringSubmatch(line); m != nil {
		kind, addr, iface = "NOFREE", m[1], m[2]
	} else if m := keaAlloc.FindStringSubmatch(line); m != nil {
		kind, addr, ip = "DHCPACK", m[1], m[2]
	} else if m := keaRelease.FindStringSubmatch(line); m != nil {
		kind, addr, ip = "DHCPRELEASE", m[1], m[2]
	} else if m := keaNoFree.FindStringSubmatch(line); m != nil {
		kind, addr = "NOFREE", m[1]
	} else {
		return
	}
	addr = strings.ToLower(addr)
	reason := ""
	if kind == "DHCPNAK" {
		// dnsmasq puts the refusal reason where ACK has the hostname.
		reason, host = host, ""
	}
	if host == "*" || strings.ContainsAny(host, " \t") {
		host = ""
	}
	source := "DHCP"
	if iface != "" {
		source = "DHCP " + iface
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	known := l.leases[addr]
	if kind == "DHCPACK" && known.ip == ip {
		return
	}
	if host == "" {
		host = known.host
	}
	who := l.Names.client(addr, host)
	switch kind {
	case "DHCPACK":
		if l.leases == nil || len(l.leases) >= lanStateLimit {
			l.leases = map[string]lease{}
		}
		l.leases[addr] = lease{ip, host}
		l.Log.Add(at, DHCP, Info, source, who+" получил "+ip)
	case "DHCPRELEASE":
		delete(l.leases, addr)
		l.Log.Add(at, DHCP, Info, source, who+" освободил "+ip)
	case "DHCPNAK":
		delete(l.leases, addr)
		msg := who + ": отказ в адресе " + ip
		if reason != "" {
			msg += " (" + reason + ")"
		}
		l.Log.Add(at, DHCP, Warning, source, msg)
	case "NOFREE":
		l.Log.Add(at, DHCP, Error, source, who+": нет свободных адресов")
	}
}
