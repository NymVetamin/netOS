package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const diagnosticCaptureLimit = 8 << 20
const diagnosticTextLimit = 64 << 10

type diagnosticInput struct {
	Kind      string `json:"kind"`
	Host      string `json:"host"`
	Interface string `json:"interface"`
	Duration  int    `json:"duration"`
	Count     int    `json:"count"`
	Size      int    `json:"size"`
	Port      int    `json:"port"`
	TTL       int    `json:"ttl"`
	Filter    string `json:"filter"`
	DNSServer string `json:"dns_server"`
	QueryType string `json:"query_type"`
	Mode      string `json:"mode"`
	Bind      string `json:"bind"`
	UDP       bool   `json:"udp"`
	Reverse   bool   `json:"reverse"`
	Mbps      int    `json:"mbps"`
}

type diagnosticCommand struct {
	name     string
	args     []string
	duration time.Duration
}

func diagnosticHost(host string) bool {
	return len(host) <= 253 && !strings.Contains(host, "..") && (net.ParseIP(host) != nil || probeHostname.MatchString(host))
}

// Every field becomes one argv element; no shell, filenames or user-supplied flags.
func buildDiagnosticCommand(in diagnosticInput) (diagnosticCommand, error) {
	c := diagnosticCommand{duration: 30 * time.Second}
	bad := func(message string) (diagnosticCommand, error) { return c, errors.New(message) }
	if in.Duration == 0 {
		in.Duration = 10
	}
	if in.Duration < 1 || in.Duration > 60 {
		return bad("длительность должна быть от 1 до 60 секунд")
	}
	if in.Interface != "" {
		if _, err := net.InterfaceByName(in.Interface); err != nil {
			return bad("интерфейс не найден")
		}
	}
	if in.Kind == "ping" || in.Kind == "traceroute" || in.Kind == "mtr" || in.Kind == "dns" || (in.Kind == "iperf" && in.Mode != "server") {
		if !diagnosticHost(in.Host) {
			return bad("укажите IP-адрес или имя узла")
		}
	}
	switch in.Kind {
	case "ping":
		if in.Count == 0 {
			in.Count = 5
		}
		if in.Size == 0 {
			in.Size = 56
		}
		if in.Count < 1 || in.Count > 30 || in.Size < 16 || in.Size > 1472 {
			return bad("ping: 1–30 пакетов, размер 16–1472 байт")
		}
		c.name, c.args = "ping", []string{"-4", "-n", "-c", strconv.Itoa(in.Count), "-W", "2", "-s", strconv.Itoa(in.Size)}
		c.duration = time.Duration(in.Count+5) * time.Second
		if in.Interface != "" {
			c.args = append(c.args, "-I", in.Interface)
		}
		c.args = append(c.args, "--", in.Host)
	case "traceroute", "mtr":
		if in.TTL == 0 {
			in.TTL = 30
		}
		if in.TTL < 1 || in.TTL > 64 {
			return bad("максимальный TTL: 1–64")
		}
		c.duration = 75 * time.Second
		c.name, c.args = "traceroute", []string{"-4", "-n", "-m", strconv.Itoa(in.TTL), "-w", "1", "-q", "1"}
		if in.Interface != "" {
			c.args = append(c.args, "-i", in.Interface)
		}
		if in.Kind == "mtr" {
			c.name, c.args = "mtr", []string{"-4", "-n", "-r", "-w", "-c", "5", "-m", strconv.Itoa(in.TTL)}
			if in.Interface != "" {
				c.args = append(c.args, "-I", in.Interface)
			}
		}
		c.args = append(c.args, "--", in.Host)
	case "dns":
		if in.QueryType == "" {
			in.QueryType = "A"
		}
		switch in.QueryType {
		case "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR":
		default:
			return bad("неподдерживаемый тип DNS-записи")
		}
		c.name, c.args = "dig", []string{"+time=2", "+tries=1", "-q", in.Host, "-t", in.QueryType}
		if in.DNSServer != "" {
			if net.ParseIP(in.DNSServer) == nil {
				return bad("DNS-сервер должен быть IP-адресом")
			}
			c.args = append(c.args, "@"+in.DNSServer)
		}
	case "capture", "torch":
		if in.Interface == "" {
			return bad("выберите интерфейс захвата")
		}
		if len(in.Filter) > 256 || strings.ContainsAny(in.Filter, "\x00\r\n") {
			return bad("фильтр BPF: до 256 символов в одной строке")
		}
		if in.Count == 0 {
			in.Count = 10000
		}
		if in.Count < 1 || in.Count > 10000 {
			return bad("лимит захвата: 1–10000 пакетов")
		}
		if in.Size == 0 {
			in.Size = 256
		}
		if in.Kind == "torch" {
			in.Size = 128
		}
		if in.Size < 64 || in.Size > 65535 {
			return bad("длина захвата пакета: 64–65535 байт")
		}
		c.name, c.args = "tcpdump", []string{"-n", "-p", "-U", "-i", in.Interface, "-s", strconv.Itoa(in.Size), "-c", strconv.Itoa(in.Count), "-w", "-", "--"}
		if in.Filter != "" {
			c.args = append(c.args, in.Filter)
		}
		c.duration = time.Duration(in.Duration) * time.Second
	case "iperf":
		if in.Port == 0 {
			in.Port = 5201
		}
		if in.Port < 1024 || in.Port > 65535 {
			return bad("порт iPerf3: 1024–65535")
		}
		if in.Mbps == 0 {
			in.Mbps = 100
		}
		if in.Mbps < 1 || in.Mbps > 10000 {
			return bad("скорость: 1–10000 Мбит/с")
		}
		c.name, c.args = "iperf3", []string{"-4", "--forceflush", "-p", strconv.Itoa(in.Port)}
		if in.Bind != "" {
			if !diagnosticLocalIP(in.Bind) {
				return bad("выберите локальный IPv4-адрес")
			}
			c.args = append(c.args, "-B", in.Bind)
		}
		if in.Mode == "server" {
			if in.Bind == "" {
				return bad("укажите локальный адрес временного сервера")
			}
			c.args = append(c.args, "-s", "-1")
			c.duration = time.Duration(in.Duration) * time.Second
		} else if in.Mode == "" || in.Mode == "client" {
			c.args = append(c.args, "-c", in.Host, "-t", strconv.Itoa(in.Duration), "-b", strconv.Itoa(in.Mbps)+"M", "--connect-timeout", "3000")
			if in.UDP {
				c.args = append(c.args, "-u")
			}
			if in.Reverse {
				c.args = append(c.args, "-R")
			}
			c.duration = time.Duration(in.Duration+10) * time.Second
		} else {
			return bad("неизвестный режим iPerf3")
		}
	case "connections":
		c.name, c.args = "ss", []string{"-t", "-u", "-n", "-a", "-p"}
	case "route":
		if net.ParseIP(in.Host).To4() == nil {
			return bad("для поиска маршрута укажите IPv4-адрес")
		}
		c.name, c.args = "ip", []string{"-4", "route", "get", in.Host}
	default:
		return bad("неизвестный инструмент")
	}
	return c, nil
}

func diagnosticLocalIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
		return false
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addresses {
		local, _, _ := net.ParseCIDR(a.String())
		if ip.Equal(local) {
			return true
		}
	}
	return false
}

func (s *Server) handleDiagnosticTools(w http.ResponseWriter, r *http.Request) {
	available := map[string]bool{}
	for kind, binary := range map[string]string{"ping": "ping", "traceroute": "traceroute", "mtr": "mtr", "dns": "dig", "capture": "tcpdump", "torch": "tcpdump", "iperf": "iperf3", "connections": "ss", "route": "ip"} {
		_, err := exec.LookPath(binary)
		available[kind] = err == nil
	}
	type iface struct {
		Name      string   `json:"name"`
		Addresses []string `json:"addresses"`
	}
	interfaces := []iface{}
	list, err := net.Interfaces()
	if err != nil {
		writeError(w, 500, "не удалось прочитать интерфейсы")
		return
	}
	for _, item := range list {
		entry := iface{Name: item.Name, Addresses: []string{}}
		addrs, _ := item.Addrs()
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip.To4() != nil {
				entry.Addresses = append(entry.Addresses, ip.String())
			}
		}
		interfaces = append(interfaces, entry)
	}
	writeJSON(w, 200, map[string]any{"available": available, "interfaces": interfaces})
}

type diagnosticManager struct {
	mu     sync.Mutex
	jobs   map[string]*diagnosticJob
	active bool
}
type diagnosticJob struct {
	mu                              sync.Mutex
	id, owner, kind, failure, state string
	output                          bytes.Buffer
	started                         time.Time
	finished                        time.Time
	cancel                          context.CancelFunc
	pcap                            []byte
	torch                           *torchReader
	truncated                       bool
	expiry                          *time.Timer
}

func (s *Server) handleDiagnosticStart(w http.ResponseWriter, r *http.Request) {
	var input diagnosticInput
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		writeError(w, 400, "некорректные параметры")
		return
	}
	command, err := buildDiagnosticCommand(input)
	if err != nil {
		writeError(w, 400, "%s", err)
		return
	}
	path, err := exec.LookPath(command.name)
	if err != nil {
		writeError(w, 503, "%s не установлен; установите соответствующий компонент", command.name)
		return
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		writeError(w, 500, "не удалось создать запуск")
		return
	}
	// Jobs outlive the POST but have a hard deadline even if the browser disappears.
	ctx, cancel := context.WithTimeout(context.Background(), command.duration)
	j := &diagnosticJob{id: hex.EncodeToString(idBytes), owner: userOf(r), kind: input.Kind, started: time.Now(), state: "running", cancel: cancel}
	if input.Kind == "torch" {
		j.torch = newTorchReader()
	}
	m := &s.diagnostics
	m.mu.Lock()
	if m.active {
		m.mu.Unlock()
		cancel()
		writeError(w, 409, "уже выполняется диагностический запуск; дождитесь завершения")
		return
	}
	if m.jobs == nil {
		m.jobs = make(map[string]*diagnosticJob)
	}
	if len(m.jobs) >= 4 {
		var oldest *diagnosticJob
		for _, previous := range m.jobs {
			if oldest == nil || previous.started.Before(oldest.started) {
				oldest = previous
			}
		}
		delete(m.jobs, oldest.id)
		if oldest.expiry != nil {
			oldest.expiry.Stop()
		}
	}
	m.active = true
	m.jobs[j.id] = j
	m.mu.Unlock()
	go func() {
		defer cancel()
		cmd := exec.CommandContext(ctx, path, command.args...)
		cmd.Stdout = diagnosticWriter{job: j, binary: input.Kind == "capture" || input.Kind == "torch"}
		cmd.Stderr = diagnosticWriter{job: j}
		cmd.WaitDelay = 2 * time.Second
		err := cmd.Run()
		m.mu.Lock()
		j.mu.Lock()
		j.finished = time.Now()
		if j.state == "stopping" {
			j.state = "stopped"
		}
		if j.state == "running" {
			j.state = "done"
			if ctx.Err() != nil {
				if input.Kind != "capture" && input.Kind != "torch" {
					j.state = "timeout"
					j.failure = "Истекло время запуска"
				}
			} else if err != nil {
				j.state = "error"
				j.failure = err.Error()
			}
		}
		// A killed tcpdump may end midway through a record. Only complete packets are downloadable.
		if input.Kind == "capture" {
			j.pcap = completePCAP(j.pcap)
		}
		j.mu.Unlock()
		id := j.id
		m.active = false
		j.expiry = time.AfterFunc(5*time.Minute, func() { m.mu.Lock(); delete(m.jobs, id); m.mu.Unlock() })
		m.mu.Unlock()
	}()
	writeJSON(w, 202, map[string]string{"id": j.id})
}

// Output limits apply while reading, never after CombinedOutput has allocated an unbounded buffer.
type diagnosticWriter struct {
	job    *diagnosticJob
	binary bool
}

func (writer diagnosticWriter) Write(p []byte) (int, error) {
	n := len(p)
	j := writer.job
	j.mu.Lock()
	defer j.mu.Unlock()
	if writer.binary && j.torch != nil {
		n, err := j.torch.Write(p)
		if err != nil {
			j.failure = err.Error()
			j.state = "error"
			j.cancel()
		}
		return n, err
	}
	if writer.binary {
		remaining := diagnosticCaptureLimit - len(j.pcap)
		if len(p) > remaining {
			j.pcap = append(j.pcap, p[:remaining]...)
			j.truncated = true
			j.cancel()
			return len(p), nil
		}
		j.pcap = append(j.pcap, p...)
	} else {
		remaining := diagnosticTextLimit - j.output.Len()
		if len(p) > remaining {
			p = p[:remaining]
			j.truncated = true
		}
		// bounded text; use a byte buffer in the hot path rather than repeated full-string copies.
		_, _ = j.output.Write(p)
	}
	return n, nil
}

func (s *Server) diagnosticJobFor(w http.ResponseWriter, r *http.Request) *diagnosticJob {
	s.diagnostics.mu.Lock()
	j := s.diagnostics.jobs[r.PathValue("id")]
	s.diagnostics.mu.Unlock()
	if j == nil || j.owner != userOf(r) {
		writeError(w, 404, "запуск не найден или результат уже удалён")
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")
	return j
}
func (s *Server) handleDiagnosticJob(w http.ResponseWriter, r *http.Request) {
	j := s.diagnosticJobFor(w, r)
	if j == nil {
		return
	}
	j.mu.Lock()
	end := time.Now()
	if !j.finished.IsZero() {
		end = j.finished
	}
	response := map[string]any{"id": j.id, "kind": j.kind, "state": j.state, "output": j.output.String(), "error": j.failure, "elapsed": end.Sub(j.started).Seconds(), "truncated": j.truncated, "capture_bytes": len(j.pcap)}
	if j.torch != nil {
		response["torch"] = j.torch.snapshot(end.Sub(j.started).Seconds())
	}
	j.mu.Unlock()
	writeJSON(w, 200, response)
}
func (s *Server) handleDiagnosticStop(w http.ResponseWriter, r *http.Request) {
	j := s.diagnosticJobFor(w, r)
	if j == nil {
		return
	}
	j.mu.Lock()
	if j.state == "running" {
		j.state = "stopping"
		j.cancel()
	}
	j.mu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handleDiagnosticCapture(w http.ResponseWriter, r *http.Request) {
	j := s.diagnosticJobFor(w, r)
	if j == nil {
		return
	}
	j.mu.Lock()
	if j.kind != "capture" || j.finished.IsZero() {
		j.mu.Unlock()
		writeError(w, 409, "захват ещё не завершён")
		return
	}
	if len(j.pcap) < 24 {
		j.mu.Unlock()
		writeError(w, 404, "нет данных PCAP")
		return
	}
	data := j.pcap // immutable after finished; a slow download must not block job status.
	j.mu.Unlock()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="netos-%s.pcap"`, j.id))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = io.Copy(w, bytes.NewReader(data))
}
