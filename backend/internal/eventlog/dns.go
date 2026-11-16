package eventlog

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Only queries are shown: replies, forwards and cache hits repeat them.
var (
	dnsmasqQuery     = regexp.MustCompile(`\bquery\[([A-Za-z0-9]+)\]\s+(\S+)\s+from\s+(\S+)`)
	unboundQuery     = regexp.MustCompile(`(?:info:|query:)\s+(\S+)\s+(\S+)\s+([A-Z0-9]+)\s+(?:IN|CH|HS|CLASS[0-9]+)\s*$`)
	dnsproxyQuestion = regexp.MustCompile(`^;([^;\s]+)\s+(?:IN|CH|HS|CLASS[0-9]+)\s+([A-Z0-9]+)\s*$`)
	dnsproxyLine     = regexp.MustCompile(`\bline=("(?:\\.|[^"\\])*"|\S+)`)
)

// DNSQuery formats a resolver's query line as "name (TYPE)" with the client
// address as source. dnsproxy prints the question without the client.
func DNSQuery(line string) (client, text string, ok bool) {
	// The literal checks are what each pattern requires anyway; replies,
	// forwards and cache lines (most of the stream) skip the regexps.
	if strings.Contains(line, "query[") {
		if m := dnsmasqQuery.FindStringSubmatch(line); m != nil {
			return m[3], strings.TrimSuffix(m[2], ".") + " (" + m[1] + ")", true
		}
	}
	if strings.Contains(line, "info:") || strings.Contains(line, "query:") {
		if m := unboundQuery.FindStringSubmatch(line); m != nil {
			if _, err := netip.ParseAddr(m[1]); err == nil {
				return m[1], strings.TrimSuffix(m[2], ".") + " (" + m[3] + ")", true
			}
		}
	}
	question := ""
	if strings.Contains(line, "msg=in ") || strings.Contains(line, `msg="in" `) {
		if m := dnsproxyLine.FindStringSubmatch(line); m != nil {
			question = m[1]
			if strings.HasPrefix(question, `"`) {
				question, _ = strconv.Unquote(question)
			}
		}
	} else if _, after, found := strings.Cut(line, "in: "); found {
		question = strings.TrimSpace(after)
	}
	if question == "" {
		return "", "", false
	}
	if m := dnsproxyQuestion.FindStringSubmatch(question); m != nil {
		return "dnsproxy", strings.TrimSuffix(m[1], ".") + " (" + m[2] + ")", true
	}
	return "", "", false
}
