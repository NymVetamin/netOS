package eventlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
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

const journalFields = "__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,MESSAGE_ID,_PID,_TRANSPORT,SYSLOG_IDENTIFIER,UNIT,JOB_TYPE,JOB_RESULT,UNIT_RESULT,EXIT_CODE,EXIT_STATUS,INVOCATION_ID"

// journalMatches selects only what some topic shows; journald filters by its
// indexes, so unrelated daemon output never reaches netosd.
var journalMatches = []string{
	"_PID=1", "MESSAGE_ID=" + msgStarted, "MESSAGE_ID=" + msgJobFailed, "MESSAGE_ID=" + msgStopped, "MESSAGE_ID=" + msgExit, "MESSAGE_ID=" + msgFailed,
	"+", "_TRANSPORT=kernel",
	"+", "SYSLOG_IDENTIFIER=sshd",
	"+", "SYSLOG_IDENTIFIER=sshd-session",
}

const maxJournalLine = 64 << 10

// Journal turns journald records into events. It is owned by one goroutine.
type Journal struct {
	Log *Log
	// Reason returns the last line a failed unit invocation logged; optional.
	Reason func(ctx context.Context, invocation string) string
	units  map[string]*unitState
	cursor string
}

type unitState struct {
	failed, restarting bool
	exit               string
}

// Follow runs one journalctl process for the daemon's lifetime. The first run
// refills the log from recent history; a restarted process continues after
// the last cursor, so nothing is shown twice.
func (j *Journal) Follow(ctx context.Context) {
	for ctx.Err() == nil {
		args := []string{"--follow", "--output=json", "--output-fields=" + journalFields}
		if j.cursor == "" {
			args = append(args, "--lines="+strconv.Itoa(3*Size))
		} else {
			args = append(args, "--lines=all", "--after-cursor="+j.cursor)
		}
		cmd := exec.CommandContext(ctx, "journalctl", append(args, journalMatches...)...)
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
// fresh enough to look up its reason (never during the start-up refill).
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
		if j.Reason != nil && rec["INVOCATION_ID"] != "" && now.Sub(at) < time.Minute {
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
	case len(f) >= 5 && f[0] == "Invalid" && f[1] == "user" && f[3] == "from":
		return Warning, "неудачный вход " + f[2] + " с " + f[4] + ": нет такого пользователя", true
	case len(f) >= 4 && f[0] == "Failed" && f[2] == "for" && f[3] == "invalid":
		return "", "", false
	case len(f) >= 6 && f[0] == "Failed" && f[2] == "for" && f[4] == "from":
		return Warning, "неудачный вход " + f[3] + " с " + f[5] + ": неверный пароль или ключ", true
	case len(f) >= 5 && f[0] == "Disconnected" && f[1] == "from" && f[2] == "user":
		return Info, "выход " + f[3] + " (" + f[4] + ")", true
	}
	return "", "", false
}
