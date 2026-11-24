package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/system"
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
// historical journals. The optional query file is read by the panel's single
// DNSFileTail, which also feeds AddDNS.
func (h *ClientHistory) watchDNS(ctx context.Context) {
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
				h.noteLimitLocked("resource-buffer", now.Unix(), now.Unix())
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
				at := time.Now().Unix()
				h.noteLimitLocked("journal", at, at)
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

// DNSFileTail drains a renamed inode before switching to the new file. Only
// the first attachment skips history; a rotated file must be read from byte 0.
type DNSFileTail struct {
	mu             sync.Mutex
	file           *os.File
	offset         int64
	pending        string
	archives       []dnsTailArchive
	discardPartial bool
}

type dnsTailArchive struct {
	file    *os.File
	gap     bool
	midLine bool
}

func (t *DNSFileTail) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range t.archives {
		_ = a.file.Close()
	}
	if t.file != nil {
		_ = t.file.Close()
	}
	t.file, t.archives, t.pending, t.offset, t.discardPartial = nil, nil, "", 0, false
}

// CopyTruncate hands the unread archived bytes to the reader before resetting
// its live cursor. An unsuccessful truncate leaves both cursors untouched.
func (t *DNSFileTail) CopyTruncate(live *os.File, archived os.FileInfo, start int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return live.Truncate(0)
	}
	current, err := t.file.Stat()
	if err != nil {
		return err
	}
	source, err := live.Stat()
	if err != nil {
		return err
	}
	same := os.SameFile(current, source)
	offset := int64(0)
	if same {
		offset = t.offset
		if offset >= start+archived.Size() {
			if err := live.Truncate(0); err != nil {
				return err
			}
			t.offset = 0
			return nil
		}
	}
	archive, err := system.OpenSameRegular(live.Name()+".1", archived)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = archive.Close()
		}
	}()
	if _, err = archive.Seek(max(int64(0), offset-start), io.SeekStart); err != nil {
		return err
	}
	entry := dnsTailArchive{file: archive, gap: offset < start || !same}
	if offset < start {
		var previous [1]byte
		if _, err := live.ReadAt(previous[:], start-1); err != nil {
			return err
		}
		entry.midLine = previous[0] != '\n'
	}
	next := t.file
	if !same {
		next, err = system.OpenSameRegular(live.Name(), source)
		if err != nil {
			return err
		}
		// An earlier rename left this reader on the older inode.
		if _, err = t.file.Seek(t.offset, io.SeekStart); err != nil {
			_ = next.Close()
			return err
		}
	}
	if err := live.Truncate(0); err != nil {
		if !same {
			_ = next.Close()
		}
		return err
	}
	if !same {
		t.archives = append(t.archives, dnsTailArchive{file: t.file})
	}
	t.archives = append(t.archives, entry)
	keep = true
	t.file, t.offset = next, 0
	for len(t.archives) > 3 {
		dropped := t.archives[0].file
		t.archives = t.archives[1:]
		first := &t.archives[0]
		if !first.gap {
			// A record can straddle a copytruncate. Do not emit its suffix
			// as a new record after the preceding archive expires.
			var last [1]byte
			end, err := dropped.Seek(-1, io.SeekEnd)
			first.midLine = true
			if err == nil {
				if _, err := dropped.ReadAt(last[:], end); err == nil {
					first.midLine = last[0] != '\n'
				}
			}
			first.gap = true
		}
		_ = dropped.Close()
	}
	return nil
}

func (t *DNSFileTail) Read(path string) ([]string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.archives) > 0 {
		entry := &t.archives[0]
		if entry.gap {
			t.pending = ""
			t.discardPartial = entry.midLine
			entry.gap = false
		}
		data, err := io.ReadAll(io.LimitReader(entry.file, 256<<10))
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			return t.lines(data), nil
		}
		_ = entry.file.Close()
		t.archives = t.archives[1:]
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if t.file == nil {
		t.file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		t.offset, err = t.file.Seek(0, io.SeekEnd)
		return nil, err
	}
	old, err := t.file.Stat()
	if err != nil {
		return nil, err
	}
	rotated := !os.SameFile(old, info)
	if old.Size() < t.offset {
		t.offset, t.pending, t.discardPartial = 0, "", false
	}
	data, err := io.ReadAll(io.NewSectionReader(t.file, t.offset, 256<<10))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 && rotated {
		next, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		_ = t.file.Close()
		t.file, t.offset, t.pending, t.discardPartial = next, 0, "", false
		data, err = io.ReadAll(io.NewSectionReader(t.file, t.offset, 256<<10))
		if err != nil {
			return nil, err
		}
	}
	t.offset += int64(len(data))
	return t.lines(data), nil
}

func (t *DNSFileTail) lines(data []byte) []string {
	if t.discardPartial {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil
		}
		data = data[i+1:]
		t.discardPartial = false
	}
	parts := strings.Split(t.pending+string(data), "\n")
	t.pending = parts[len(parts)-1]
	if len(t.pending) > 8192 {
		t.pending = ""
	}
	return parts[:len(parts)-1]
}
