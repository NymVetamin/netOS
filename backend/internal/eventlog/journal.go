package eventlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// systemd catalog IDs (catalog/systemd.catalog.in).
const (
	msgStarted   = "39f53479d3a045ac8e11786248231fbf"
	msgJobFailed = "be02cf6855d2428ba40df7e9d022f03d"
	msgStopped   = "9d1aaa27d60140bd96365438aad20286"
	msgExit      = "98e322203f7a4ed290d09fe03c09fe15"
	msgFailed    = "d9b373ed55a64feb8242e02dbe79a49c"
)

const journalFields = "__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,MESSAGE_ID,_PID,_TRANSPORT,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,UNIT,JOB_TYPE,JOB_RESULT,UNIT_RESULT,EXIT_CODE,EXIT_STATUS,INVOCATION_ID,IKE_SA_NAME"

const unboundUnit = "netos-unbound.service"

// journalGroups select only what some topic shows; journald filters by its
// indexes, so unrelated daemon output never reaches netosd. Each group is one
// OR-branch of the live filter and is refilled separately on start, so a
// chatty source (DNS queries, a LOG rule) cannot push the others out.
//
// One unit is not filtered that finely: while the traffic monitor is on and
// the query log is off, dnsmasq prints its DNS traffic to journald under the
// DHCP unit, with no field telling the two apart. Those lines are dropped by
// LAN.DHCP at a substring check (journald's rate limit bounds their number),
// but they do fill the unit's newest Size records, so DHCP history is not
// refilled after a restart in that mode — as with dns.log.
var journalGroups = [][]string{
	{"_PID=1", "MESSAGE_ID=" + msgStarted, "MESSAGE_ID=" + msgJobFailed, "MESSAGE_ID=" + msgStopped, "MESSAGE_ID=" + msgExit, "MESSAGE_ID=" + msgFailed},
	{"_TRANSPORT=kernel"},
	{"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"},
	{"_SYSTEMD_UNIT=" + unboundUnit},
	// VPN daemons: only authentication refusals are taken from them.
	{"SYSLOG_IDENTIFIER=ocserv", "SYSLOG_IDENTIFIER=charon-systemd", "SYSLOG_IDENTIFIER=pppd"},
	{"SYSLOG_IDENTIFIER=hostapd"},
	{"_SYSTEMD_UNIT=" + dhcpUnits[0], "_SYSTEMD_UNIT=" + dhcpUnits[1], "_SYSTEMD_UNIT=" + dhcpUnits[2]},
}

var dhcpUnits = [...]string{"netos-dnsmasq.service", "netos-isc-dhcp.service", "netos-kea-dhcp4.service"}

func journalMatches() []string {
	var out []string
	for i, g := range journalGroups {
		if i > 0 {
			out = append(out, "+")
		}
		out = append(out, g...)
	}
	return out
}

const maxJournalLine = 64 << 10

// Journal turns journald records into events. It is owned by one goroutine.
type Journal struct {
	Log *Log
	// Reason returns the last line a failed unit invocation logged; optional.
	Reason func(ctx context.Context, invocation string) string
	// DNS reports whether DNS queries are shown (the query log is enabled).
	DNS func() bool
	// LAN receives hostapd and DHCP server lines; optional.
	LAN *LAN
	// VPNServer names a VPN server by type and index; optional.
	VPNServer func(typ string, index int) string
	// Run executes journalctl and returns its output; tests replace it.
	Run    func(ctx context.Context, args ...string) ([]byte, error)
	units  map[string]*unitState
	cursor string
}

type unitState struct {
	failed, restarting bool
	exit               string
}

// Follow runs one journalctl process for the daemon's lifetime. On start each
// group is refilled from recent history up to the current end of the journal,
// and the live process continues exactly after it; a restarted process
// continues after the last cursor, so nothing is shown twice or skipped.
func (j *Journal) Follow(ctx context.Context) {
	for ctx.Err() == nil {
		if j.cursor == "" {
			j.refill(ctx)
		}
		args := []string{"--follow", "--output=json", "--output-fields=" + journalFields}
		if j.cursor == "" {
			args = append(args, "--lines=0")
		} else {
			args = append(args, "--lines=all", "--after-cursor="+j.cursor)
		}
		cmd := exec.CommandContext(ctx, "journalctl", append(args, journalMatches()...)...)
		pipe, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			j.read(ctx, pipe)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (j *Journal) run(ctx context.Context, args ...string) ([]byte, error) {
	if j.Run != nil {
		return j.Run(ctx, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "journalctl", append([]string{"--no-pager", "--quiet"}, args...)...).Output()
}

// refill loads the newest Size records of every group, up to the journal's
// current last entry, and handles them in time order. Runs once per daemon
// start: 2 + len(journalGroups) commands.
func (j *Journal) refill(ctx context.Context) {
	out, err := j.run(ctx, "--output=json", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP", "--lines=1")
	if err != nil {
		return
	}
	head, err := parseRecord(bytes.TrimSpace(out))
	if err != nil {
		return
	}
	us, err := strconv.ParseInt(head["__REALTIME_TIMESTAMP"], 10, 64)
	if err != nil {
		return
	}
	until := "--until=@" + strconv.FormatInt(us/1e6, 10) + "." + fmt.Sprintf("%06d", us%1e6)
	type row struct {
		at  int64
		raw []byte
	}
	var rows []row
	for _, g := range journalGroups {
		out, err := j.run(ctx, append([]string{"--output=json", "--output-fields=" + journalFields, "--lines=" + strconv.Itoa(Size), until}, g...)...)
		if err != nil {
			continue // an empty group is reported as an error by old journalctl
		}
		for _, line := range bytes.Split(out, []byte{'\n'}) {
			if len(line) == 0 || len(line) > maxJournalLine {
				continue
			}
			var ts struct {
				T string `json:"__REALTIME_TIMESTAMP"`
			}
			if json.Unmarshal(line, &ts) != nil {
				continue
			}
			at, _ := strconv.ParseInt(ts.T, 10, 64)
			rows = append(rows, row{at, line})
		}
	}
	// Each group is already in journal order; a stable sort keeps it.
	sort.SliceStable(rows, func(a, b int) bool { return rows[a].at < rows[b].at })
	// The zero time marks history: no reason lookups, or a unit that kept
	// failing before the start would cost a command per failure.
	for _, r := range rows {
		j.Handle(ctx, r.raw, time.Time{})
	}
	j.cursor = head["__CURSOR"]
}

func (j *Journal) read(ctx context.Context, r io.Reader) {
	br := bufio.NewReaderSize(r, 16<<10)
	var line []byte
	skipping := false
	for {
		part, prefix, err := br.ReadLine()
		if err != nil {
			return
		}
		// Overlong records are skipped whole instead of stopping the stream.
		if skipping || len(line)+len(part) > maxJournalLine {
			skipping, line = prefix, line[:0]
			continue
		}
		line = append(line, part...)
		if prefix {
			continue
		}
		j.Handle(ctx, line, time.Now())
		line = line[:0]
	}
}

type journalRecord map[string]string

func parseRecord(raw []byte) (journalRecord, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	rec := journalRecord{}
	for k, v := range fields {
		var s string
		// Non-UTF-8 values arrive as byte arrays; they carry nothing we show.
		if json.Unmarshal(v, &s) == nil {
			rec[k] = s
		}
	}
	if rec["__CURSOR"] == "" {
		return nil, errors.New("journal record without cursor")
	}
	return rec, nil
}

// Handle classifies one journal JSON line; now decides whether a failure is
// fresh enough to look up its reason. The zero now is the start-up refill,
// which never looks reasons up.
func (j *Journal) Handle(ctx context.Context, raw []byte, now time.Time) {
	rec, err := parseRecord(raw)
	if err != nil {
		return
	}
	j.cursor = rec["__CURSOR"]
	us, _ := strconv.ParseInt(rec["__REALTIME_TIMESTAMP"], 10, 64)
	at := time.UnixMicro(us)
	switch {
	case rec["_PID"] == "1":
		j.unit(ctx, rec, at, now)
	case rec["_TRANSPORT"] == "kernel":
		if rule, msg, ok := FirewallEvent(rec["MESSAGE"]); ok {
			j.Log.Add(at, Firewall, Info, rule, msg)
		}
	case j.LAN != nil && rec["SYSLOG_IDENTIFIER"] == "hostapd":
		j.LAN.WiFi(at, rec["MESSAGE"])
	case j.LAN != nil && (rec["_SYSTEMD_UNIT"] == dhcpUnits[0] || rec["_SYSTEMD_UNIT"] == dhcpUnits[1] || rec["_SYSTEMD_UNIT"] == dhcpUnits[2]):
		j.LAN.DHCP(at, rec["MESSAGE"])
	case rec["_SYSTEMD_UNIT"] == unboundUnit:
		if j.DNS != nil && j.DNS() {
			if client, msg, ok := DNSQuery(rec["MESSAGE"]); ok {
				j.Log.Add(at, DNS, Info, client, msg)
			}
		}
	case rec["SYSLOG_IDENTIFIER"] == "ocserv" || rec["SYSLOG_IDENTIFIER"] == "charon-systemd" || rec["SYSLOG_IDENTIFIER"] == "pppd":
		if typ, index, msg, ok := VPNRefusal(rec); ok {
			source := ""
			if j.VPNServer != nil {
				source = j.VPNServer(typ, index)
			}
			if source == "" {
				source = vpnTypeNames[typ]
			}
			j.Log.Add(at, VPN, Warning, source, msg)
		}
	case strings.HasPrefix(rec["SYSLOG_IDENTIFIER"], "sshd"):
		if level, msg, ok := SSHEvent(rec["MESSAGE"]); ok {
			j.Log.Add(at, Access, level, "SSH", msg)
		}
	}
}

var unitResults = map[string]string{
	"exit-code":       "процесс завершился с ошибкой",
	"signal":          "процесс убит сигналом",
	"core-dump":       "аварийное завершение",
	"timeout":         "не уложилась во время ожидания",
	"watchdog":        "перестала отвечать",
	"start-limit-hit": "слишком частые перезапуски, попытки прекращены",
	"resources":       "не хватило ресурсов для запуска",
	"oom-kill":        "убита из-за нехватки памяти",
	"protocol":        "нарушила протокол запуска",
	"dependency":      "не запустилась зависимость",
}

// Only netOS units are shown: restarts of unrelated system units would bury
// the services the panel manages.
func (j *Journal) unit(ctx context.Context, rec journalRecord, at, now time.Time) {
	name := rec["UNIT"]
	if !strings.HasPrefix(name, "netos") {
		return
	}
	if j.units == nil {
		j.units = map[string]*unitState{}
	}
	st := j.units[name]
	if st == nil {
		st = &unitState{}
		j.units[name] = st
	}
	source := strings.TrimSuffix(name, ".service")
	switch rec["MESSAGE_ID"] {
	case msgExit:
		switch rec["EXIT_CODE"] {
		case "exited":
			st.exit = "код " + rec["EXIT_STATUS"]
		case "killed", "dumped":
			st.exit = "сигнал " + rec["EXIT_STATUS"]
		}
		return
	case msgFailed:
		// systemd 257 reports a start-limit refusal as a second failure with
		// the previous result and no new process exit.
		if st.failed && st.exit == "" {
			j.Log.Add(at, Services, Error, source, "перезапуски прекращены: слишком частые сбои")
			return
		}
		msg := "сбой: " + resultText(rec["UNIT_RESULT"])
		if st.exit != "" {
			msg += " (" + st.exit + ")"
		}
		if j.Reason != nil && rec["INVOCATION_ID"] != "" && !now.IsZero() && now.Sub(at) < time.Minute {
			if reason := j.Reason(ctx, rec["INVOCATION_ID"]); reason != "" {
				msg += ": " + reason
			}
		}
		st.failed, st.exit = true, ""
		j.Log.Add(at, Services, Error, source, msg)
		return
	case msgJobFailed:
		// A failed unit also reports its failed start job; one event is enough.
		if !st.failed {
			st.failed = true
			j.Log.Add(at, Services, Error, source, "не запустилась: "+resultText(rec["JOB_RESULT"]))
		}
		return
	case msgStopped:
		// A restart is shown once, when the unit is running again.
		if rec["JOB_TYPE"] == "restart" {
			st.restarting = true
			return
		}
		if !st.failed {
			j.Log.Add(at, Services, Info, source, "остановлена")
		}
	case msgStarted:
		switch {
		case st.failed:
			j.Log.Add(at, Services, Info, source, "снова запущена после сбоя")
		case st.restarting:
			j.Log.Add(at, Services, Info, source, "перезапущена")
		default:
			j.Log.Add(at, Services, Info, source, "запущена")
		}
	}
	delete(j.units, name)
}

func resultText(result string) string {
	if text := unitResults[result]; text != "" {
		return text
	}
	if result == "" {
		return "причина не сообщена"
	}
	return result
}

// FirewallEvent formats a LOG line of a netOS rule ("netos <rule>: IN=... ").
func FirewallEvent(message string) (rule, text string, ok bool) {
	rest, found := strings.CutPrefix(message, "netos ")
	if !found {
		return "", "", false
	}
	rule, fields, found := strings.Cut(rest, ": ")
	if !found {
		return "", "", false
	}
	kv := map[string]string{}
	for _, f := range strings.Fields(fields) {
		if k, v, ok := strings.Cut(f, "="); ok {
			kv[k] = v
		}
	}
	if kv["SRC"] == "" {
		return "", "", false
	}
	endpoint := func(addr, port string) string {
		if strings.Contains(addr, ":") {
			addr = "[" + addr + "]"
		}
		if port == "" {
			return addr
		}
		return addr + ":" + port
	}
	text = kv["PROTO"] + " " + endpoint(kv["SRC"], kv["SPT"]) + " → " + endpoint(kv["DST"], kv["DPT"])
	if kv["PROTO"] == "ICMP" || kv["PROTO"] == "ICMPv6" {
		text += " тип " + kv["TYPE"]
	}
	if kv["IN"] != "" {
		text += ", вход " + kv["IN"]
	}
	if kv["OUT"] != "" {
		text += ", выход " + kv["OUT"]
	}
	return rule, strings.TrimSpace(text), true
}

var sshMethods = map[string]string{"password": "пароль", "publickey": "ключ", "keyboard-interactive/pam": "пароль", "keyboard-interactive": "пароль"}

// SSHEvent keeps logins, failures and logouts. An unknown user is reported
// once, by its "Invalid user" line: probes without a password attempt log
// nothing else, and the "Failed ... for invalid user" that may follow repeats it.
func SSHEvent(message string) (level, text string, ok bool) {
	f := strings.Fields(message)
	switch {
	case len(f) >= 6 && f[0] == "Accepted" && f[2] == "for" && f[4] == "from":
		method := sshMethods[f[1]]
		if method == "" {
			method = f[1]
		}
		return Info, "вход " + f[3] + " с " + f[5] + " (" + method + ")", true
	case len(f) >= 2 && f[0] == "Invalid" && f[1] == "user":
		// The name is whatever the client sent, spaces included ("root from
		// 10.0.0.5"); sshd appends "from <address> port <n>" itself, so the
		// address follows the last "from", never the first.
		at := len(f) - 1
		for at > 2 && f[at] != "from" {
			at--
		}
		if at <= 2 || at+1 >= len(f) {
			return "", "", false
		}
		return Warning, "неудачный вход " + strings.Join(f[2:at], " ") + " с " + f[at+1] + ": нет такого пользователя", true
	case len(f) >= 4 && f[0] == "Failed" && f[2] == "for" && f[3] == "invalid":
		return "", "", false
	case len(f) >= 6 && f[0] == "Failed" && f[2] == "for" && f[4] == "from":
		return Warning, "неудачный вход " + f[3] + " с " + f[5] + ": неверный пароль или ключ", true
	case len(f) >= 5 && f[0] == "Disconnected" && f[1] == "from" && f[2] == "user":
		return Info, "выход " + f[3] + " (" + f[4] + ")", true
	}
	return "", "", false
}
