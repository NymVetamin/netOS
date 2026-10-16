package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var monitorDNSMasq = regexp.MustCompile(`\bquery\[[^\]]+\]\s+(\S+)\s+from\s+(\S+)`)
var monitorUnbound = regexp.MustCompile(`(?:info:|query:)\s+(\S+)\s+(\S+)\s+[A-Z0-9]+\s+(?:IN|CH|HS|CLASS[0-9]+)\s*$`)

func ParseDNSQuery(line string) (address, domain string) {
	if m := monitorDNSMasq.FindStringSubmatch(line); len(m) == 3 {
		return m[2], m[1]
	}
	if m := monitorUnbound.FindStringSubmatch(line); len(m) == 3 {
		return m[1], m[2]
	}
	return "", ""
}

// A single journal subscription receives new resolver events. It never scans
// historical journals. The existing optional dnsmasq file is tailed by offset.
func (h *ClientHistory) watchDNS(ctx context.Context) {
	go h.tailDNSFile(ctx)
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--lines=0", "--output=json", "--output-fields=MESSAGE,__REALTIME_TIMESTAMP", "-u", "netos-dnsmasq.service", "-u", "netos-unbound.service")
		pipe, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			h.setDNSProblem("")
			scan := bufio.NewScanner(pipe)
			scan.Buffer(make([]byte, 4096), 65536)
			for scan.Scan() {
				var entry struct {
					Message string `json:"MESSAGE"`
					At      string `json:"__REALTIME_TIMESTAMP"`
				}
				if json.Unmarshal(scan.Bytes(), &entry) != nil {
					continue
				}
				if strings.Contains(entry.Message, "Suppressed ") && strings.Contains(entry.Message, "messages") {
					h.mu.Lock()
					h.limited = true
					h.mu.Unlock()
				}
				addr, domain := ParseDNSQuery(entry.Message)
				if addr == "" {
					continue
				}
				at := time.Now()
				if n, e := strconv.ParseInt(entry.At, 10, 64); e == nil {
					at = time.UnixMicro(n)
				}
				h.AddDNS(at, addr, domain)
			}
			_ = cmd.Wait()
		}
		if ctx.Err() == nil {
			h.setDNSProblem("Сбор DNS-запросов прерван; повторное подключение через 10 секунд")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}
func (h *ClientHistory) tailDNSFile(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var file *os.File
	var offset int64
	var pending string
	defer func() {
		if file != nil {
			file.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg := h.Current()
		if cfg == nil || !cfg.DNS.QueryLog {
			if file != nil {
				file.Close()
				file = nil
			}
			continue
		}
		info, err := os.Stat("/var/log/netos/dns.log")
		if err != nil {
			continue
		}
		if file != nil {
			old, e := file.Stat()
			if e != nil || !os.SameFile(old, info) {
				file.Close()
				file = nil
				offset = 0
				pending = ""
			}
		}
		if file == nil {
			file, err = os.Open("/var/log/netos/dns.log")
			if err != nil {
				continue
			}
			offset, _ = file.Seek(0, io.SeekEnd)
			continue
		}
		if info.Size() < offset {
			offset = 0
			pending = ""
			_, _ = file.Seek(0, io.SeekStart)
		}
		// Bounded batch. Falling behind is not allowed to allocate arbitrary memory.
		data, err := io.ReadAll(io.LimitReader(file, 256<<10))
		if err != nil {
			continue
		}
		offset += int64(len(data))
		parts := strings.Split(pending+string(data), "\n")
		pending = parts[len(parts)-1]
		if len(pending) > 8192 {
			pending = ""
		}
		for _, line := range parts[:len(parts)-1] {
			addr, domain := ParseDNSQuery(line)
			if addr != "" {
				h.AddDNS(time.Now(), addr, domain)
			}
		}
	}
}
