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
		// Match the executable, then validate the unit below: unit globs expand only
		// when journalctl starts and would miss newly added Xray servers.
		cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--lines=0", "--output=json", "--output-fields=MESSAGE,__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID", "_SYSTEMD_UNIT=netos-dnsmasq.service", "+", "_SYSTEMD_UNIT=netos-unbound.service", "+", "_COMM=xray")
		pipe, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			h.setDNSProblem("")
			h.readResourceJournal(ctx, pipe)
			_ = cmd.Process.Kill()
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

// One bounded stream reader; a timer flushes pending IP joins even on an idle journal.
func (h *ClientHistory) readResourceJournal(ctx context.Context, pipe io.Reader) {
	lines := make(chan []byte, 128)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(lines)
		scan := bufio.NewScanner(pipe)
		scan.Buffer(make([]byte, 4096), 65536)
		for scan.Scan() {
			line := append([]byte(nil), scan.Bytes()...)
			select {
			case lines <- line:
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	xray := &xrayResources{}
	for {
		xray.configure(h.Current())
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.addXrayResources(xray.flush(now))
			if xray.limited {
				h.mu.Lock()
				h.limited = true
				h.mu.Unlock()
				xray.unsafeUntil = time.Now().Add(xrayDNSWindow + xrayJoinDelay)
				xray.limited = false
			}
		case line, ok := <-lines:
			if !ok {
				return
			}
			var entry struct {
				Message    string `json:"MESSAGE"`
				At         string `json:"__REALTIME_TIMESTAMP"`
				Unit       string `json:"_SYSTEMD_UNIT"`
				Invocation string `json:"_SYSTEMD_INVOCATION_ID"`
				PID        string `json:"_PID"`
			}
			if json.Unmarshal(line, &entry) != nil {
				continue
			}
			if strings.Contains(entry.Message, "Suppressed ") && strings.Contains(entry.Message, "messages") {
				h.mu.Lock()
				h.limited = true
				h.mu.Unlock()
				xray.unsafeUntil = time.Now().Add(xrayDNSWindow + xrayJoinDelay)
			}
			at := time.Now()
			if n, e := strconv.ParseInt(entry.At, 10, 64); e == nil {
				at = time.UnixMicro(n)
			}
			if strings.HasPrefix(entry.Unit, "netos-xray-srv") {
				process := entry.Invocation
				if process == "" {
					process = entry.PID
				}
				h.addXrayResources(xray.consume(at, entry.Unit, process, entry.Message))
				continue
			}
			addr, domain := ParseDNSQuery(entry.Message)
			if addr != "" {
				h.AddDNS(at, addr, domain)
			}
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
