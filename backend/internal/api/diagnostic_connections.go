package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type connectionEndpoint struct {
	Address string `json:"address"`
	Port    string `json:"port,omitempty"`
}
type diagnosticConnection struct {
	Protocol         string             `json:"protocol"`
	State            string             `json:"state"`
	Source           connectionEndpoint `json:"source"`
	Destination      connectionEndpoint `json:"destination"`
	ReplySource      connectionEndpoint `json:"reply_source"`
	ReplyDestination connectionEndpoint `json:"reply_destination"`
	NAT              string             `json:"nat"`
	Timeout          *uint64            `json:"timeout,omitempty"`
	Packets          *uint64            `json:"packets,omitempty"`
	Bytes            *uint64            `json:"bytes,omitempty"`
	ReplyPackets     *uint64            `json:"reply_packets,omitempty"`
	ReplyBytes       *uint64            `json:"reply_bytes,omitempty"`
	Process          string             `json:"process,omitempty"`
}

func connectionNumber(s string) *uint64 {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return nil
	}
	return &n
}
func parseTrackedConnection(line string) (diagnosticConnection, bool) {
	c := diagnosticConnection{}
	at, count, src, dst := 0, 0, 0, 0
	reply := false
	for value := range strings.FieldsSeq(line) {
		index := count
		count++
		if index == 0 && (value == "ipv4" || value == "ipv6") {
			at = 2
		}
		if index < at {
			continue
		}
		if index == at {
			c.Protocol = strings.ToUpper(value)
			continue
		}
		if index == at+1 {
			continue
		}
		if index == at+2 {
			c.Timeout = connectionNumber(value)
			c.State = "TRACKED"
			continue
		}
		if index == at+3 && !strings.Contains(value, "=") && !strings.HasPrefix(value, "[") {
			c.State = value
		}
		key, v, hasValue := strings.Cut(value, "=")
		if !hasValue {
			if value == "[UNREPLIED]" {
				c.State = "UNREPLIED"
			} else if value == "[ASSURED]" && c.State == "TRACKED" {
				c.State = "ASSURED"
			}
			continue
		}
		switch key {
		case "src":
			src++
			reply = src > 1
			if reply {
				c.ReplySource.Address = v
			} else {
				c.Source.Address = v
			}
		case "dst":
			dst++
			if dst > 1 {
				c.ReplyDestination.Address = v
			} else {
				c.Destination.Address = v
			}
		case "sport":
			if reply {
				c.ReplySource.Port = v
			} else {
				c.Source.Port = v
			}
		case "dport":
			if reply {
				c.ReplyDestination.Port = v
			} else {
				c.Destination.Port = v
			}
		case "packets":
			if reply {
				c.ReplyPackets = connectionNumber(v)
			} else {
				c.Packets = connectionNumber(v)
			}
		case "bytes":
			if reply {
				c.ReplyBytes = connectionNumber(v)
			} else {
				c.Bytes = connectionNumber(v)
			}
		}
	}
	if count < 6 || count < at+4 {
		return diagnosticConnection{}, false
	}
	if src != 2 || dst != 2 || c.Timeout == nil {
		return c, false
	}
	if c.Source != c.ReplyDestination {
		c.NAT = "SNAT"
	}
	if c.Destination != c.ReplySource {
		if c.NAT != "" {
			c.NAT += " + "
		}
		c.NAT += "DNAT"
	}
	return c, true
}

func parseSocketEndpoint(s string) connectionEndpoint {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return connectionEndpoint{Address: strings.Trim(s[:i], "[]"), Port: s[i+1:]}
	}
	return connectionEndpoint{Address: s}
}
func parseSocketConnection(line string) (diagnosticConnection, bool) {
	f := strings.Fields(line)
	c := diagnosticConnection{}
	if len(f) < 6 || (f[0] != "tcp" && f[0] != "udp") {
		return c, false
	}
	c.Protocol = strings.ToUpper(f[0])
	c.State = f[1]
	c.Source = parseSocketEndpoint(f[4])
	c.Destination = parseSocketEndpoint(f[5])
	if len(f) > 6 {
		c.Process = strings.Join(f[6:], " ")
	}
	return c, true
}

type connectionFilter struct {
	prefix                     netip.Prefix
	ports                      [][2]uint16
	protocol, state, side, nat string
}

func parseConnectionFilter(r *http.Request) (connectionFilter, error) {
	q := r.URL.Query()
	f := connectionFilter{protocol: strings.ToUpper(q.Get("protocol")), state: strings.ToUpper(q.Get("state")), side: q.Get("side"), nat: q.Get("nat")}
	if f.side != "" && f.side != "either" && f.side != "src" && f.side != "dst" {
		return f, fmt.Errorf("неизвестная сторона фильтра")
	}
	if f.nat != "" && f.nat != "yes" && f.nat != "no" && f.nat != "SNAT" && f.nat != "DNAT" {
		return f, fmt.Errorf("неизвестный фильтр NAT")
	}
	if value := strings.TrimSpace(q.Get("address")); value != "" {
		if addr, err := netip.ParseAddr(value); err == nil {
			addr = addr.Unmap()
			f.prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return f, fmt.Errorf("укажите IP-адрес или подсеть CIDR")
			}
			f.prefix = prefix.Masked()
		}
	}
	if value := strings.TrimSpace(q.Get("ports")); value != "" {
		for _, part := range strings.Split(value, ",") {
			bounds := strings.Split(strings.TrimSpace(part), "-")
			if len(bounds) > 2 {
				return f, fmt.Errorf("неверный диапазон портов")
			}
			var pair [2]uint16
			for i, v := range bounds {
				n, err := strconv.ParseUint(v, 10, 16)
				if err != nil || n == 0 {
					return f, fmt.Errorf("порт должен быть от 1 до 65535")
				}
				pair[i] = uint16(n)
			}
			if len(bounds) == 1 {
				pair[1] = pair[0]
			}
			if pair[0] > pair[1] {
				return f, fmt.Errorf("неверный диапазон портов")
			}
			f.ports = append(f.ports, pair)
		}
	}
	sort.Slice(f.ports, func(i, j int) bool { return f.ports[i][0] < f.ports[j][0] })
	merged := f.ports[:0]
	for _, bounds := range f.ports {
		if len(merged) > 0 && bounds[0] <= merged[len(merged)-1][1] {
			if bounds[1] > merged[len(merged)-1][1] {
				merged[len(merged)-1][1] = bounds[1]
			}
		} else {
			merged = append(merged, bounds)
		}
	}
	f.ports = merged
	return f, nil
}
func (f connectionFilter) matches(c diagnosticConnection) bool {
	if f.protocol != "" && c.Protocol != f.protocol {
		return false
	}
	if f.state != "" && !strings.Contains(c.State, f.state) {
		return false
	}
	if f.nat == "yes" && c.NAT == "" || f.nat == "no" && c.NAT != "" {
		return false
	}
	if (f.nat == "SNAT" || f.nat == "DNAT") && !strings.Contains(c.NAT, f.nat) {
		return false
	}
	match := func(e connectionEndpoint) bool {
		if f.prefix.IsValid() {
			address := strings.SplitN(e.Address, "%", 2)[0]
			ip, err := netip.ParseAddr(address)
			if err != nil || !f.prefix.Contains(ip.Unmap()) {
				return false
			}
		}
		if len(f.ports) > 0 {
			p, err := strconv.ParseUint(e.Port, 10, 16)
			if err != nil {
				return false
			}
			at := sort.Search(len(f.ports), func(i int) bool { return uint64(f.ports[i][1]) >= p })
			if at == len(f.ports) || uint64(f.ports[at][0]) > p {
				return false
			}
		}
		return true
	}
	switch f.side {
	case "src":
		return match(c.Source)
	case "dst":
		return match(c.Destination)
	default:
		return match(c.Source) || match(c.Destination) || (c.ReplySource.Address != "" && match(c.ReplySource)) || (c.ReplyDestination.Address != "" && match(c.ReplyDestination))
	}
}

type connectionPage struct {
	Rows     []diagnosticConnection `json:"rows"`
	Total    int                    `json:"total"`
	Scanned  int                    `json:"scanned"`
	Unparsed int                    `json:"unparsed"`
	Page     int                    `json:"page"`
	Updated  string                 `json:"updated"`
}

func scanConnectionRows(reader io.Reader, parse func(string) (diagnosticConnection, bool), filter connectionFilter, result *connectionPage) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		result.Scanned++
		row, ok := parse(scanner.Text())
		if !ok {
			result.Unparsed++
			continue
		}
		if !filter.matches(row) {
			continue
		}
		if result.Total/100 == result.Page {
			result.Rows = append(result.Rows, row)
		}
		result.Total++
	}
	return scanner.Err()
}

// Stream the OS dump instead of retaining all connection rows or stdout.
func readConnections(ctx context.Context, source string, filter connectionFilter, page int) (connectionPage, error) {
	result := connectionPage{Rows: []diagnosticConnection{}, Page: page}
	commands := [][]string{{"conntrack", "-L", "-f", "ipv4", "-o", "extended"}, {"conntrack", "-L", "-f", "ipv6", "-o", "extended"}}
	parse := parseTrackedConnection
	if source == "local" {
		commands = [][]string{{"ss", "-H", "-t", "-u", "-n", "-a", "-p"}}
		parse = parseSocketConnection
	}
	for _, args := range commands {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return result, err
		}
		stderr := &diagnosticJob{}
		cmd.Stderr = diagnosticWriter{job: stderr}
		cmd.WaitDelay = time.Second
		if err = cmd.Start(); err != nil {
			return result, err
		}
		readErr := scanConnectionRows(stdout, parse, filter, &result)
		if readErr != nil {
			_ = cmd.Process.Kill()
		}
		err = cmd.Wait()
		if readErr != nil {
			return result, readErr
		}
		if err != nil {
			return result, fmt.Errorf("%s: %s (%w)", args[0], strings.TrimSpace(stderr.output.String()), err)
		}
	}
	result.Updated = time.Now().UTC().Format(time.RFC3339)
	return result, nil
}
func (s *Server) handleDiagnosticConnections(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "tracked"
	}
	if source != "tracked" && source != "local" {
		writeError(w, 400, "неизвестный источник соединений")
		return
	}
	page := 0
	if value := r.URL.Query().Get("page"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			writeError(w, 400, "неверный номер страницы")
			return
		}
		page = n
	}
	filter, err := parseConnectionFilter(r)
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := readConnections(ctx, source, filter, page)
	if err != nil {
		writeError(w, 503, "не удалось прочитать соединения: %s", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}
