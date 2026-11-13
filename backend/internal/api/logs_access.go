package api

import (
	"encoding/json"
	"github.com/netos-router/netos/internal/store"
	"regexp"
	"strings"
	"time"
)

const sshEventPattern = `^(Accepted |Failed |Invalid user |Disconnected from |Received disconnect from |Connection closed by |Connection reset by |pam_unix\(sshd:session\): session (opened|closed)|error: (maximum authentication attempts|PAM:)|.*authentication failure)`

var sshAuthentication = regexp.MustCompile(`^(Accepted|Failed) \S+ for (?:invalid user )?(\S+) from (\S+) port \d+`)
var sshInvalidUser = regexp.MustCompile(`^Invalid user (\S+) from (\S+)`)
var sshSession = regexp.MustCompile(`session (opened|closed) for user ([^\s(]+)`)
var sshDisconnect = regexp.MustCompile(`^(?:Disconnected from|Connection (?:closed|reset) by) (?:(?:authenticating|invalid) user |user )?(?:(\S+) )?([0-9a-fA-F:.]+) port \d+`)
var sshAddress = regexp.MustCompile(`(?:from |rhost=)([0-9a-fA-F:.]+)`)
var sshPAMUser = regexp.MustCompile(`(?:^|[; ])user=([^\s;]+)`)
var sshRelevant = regexp.MustCompile(sshEventPattern)

func sshLogFields(entry *logEntry) bool {
	if !sshRelevant.MatchString(entry.Message) {
		return false
	}
	entry.Protocol = "ssh"
	entry.Event = "Событие доступа SSH"
	entry.Result = "info"
	if m := sshAuthentication.FindStringSubmatch(entry.Message); m != nil {
		entry.User, entry.Address = m[2], m[3]
		if m[1] == "Accepted" {
			entry.Event = "Вход SSH разрешён"
			entry.Result = "success"
		} else {
			entry.Event = "Отказ во входе SSH"
			entry.Result = "failure"
		}
	} else if m := sshInvalidUser.FindStringSubmatch(entry.Message); m != nil {
		entry.User, entry.Address = m[1], m[2]
		entry.Event = "Неизвестный пользователь SSH"
		entry.Result = "failure"
	} else if m := sshSession.FindStringSubmatch(entry.Message); m != nil {
		entry.User = m[2]
		entry.Result = "success"
		if m[1] == "opened" {
			entry.Event = "Сеанс SSH открыт"
		} else {
			entry.Event = "Сеанс SSH закрыт"
		}
	} else {
		if m := sshPAMUser.FindStringSubmatch(entry.Message); m != nil {
			entry.User = m[1]
		}
		if m := sshDisconnect.FindStringSubmatch(entry.Message); m != nil {
			entry.User, entry.Address = m[1], m[2]
		}
		if entry.Address == "" {
			if m := sshAddress.FindStringSubmatch(entry.Message); m != nil {
				entry.Address = m[1]
			}
		}
		if strings.Contains(entry.Message, "authentication failure") || strings.HasPrefix(entry.Message, "error:") {
			entry.Event = "Ошибка аутентификации SSH"
			entry.Result = "failure"
		} else if strings.HasPrefix(entry.Message, "Disconnected from ") || strings.HasPrefix(entry.Message, "Received disconnect from ") || strings.HasPrefix(entry.Message, "Connection closed by ") || strings.HasPrefix(entry.Message, "Connection reset by ") {
			entry.Event = "Соединение SSH завершено"
		}
	}
	return true
}

func panelAccessEntry(row store.AuditEntry) (logEntry, error) {
	raw, err := json.Marshal(row)
	if err != nil {
		return logEntry{}, err
	}
	e := logEntry{Time: row.At.UTC().Format(time.RFC3339Nano), Source: "access", Protocol: "panel", Unit: "netosd.service", User: row.User, Address: row.SourceIP, Message: string(raw), Result: "success", Event: "Вход в панель"}
	if !row.Success {
		e.Result = "failure"
		e.Event = "Отказ во входе в панель"
	}
	if row.Action == "logout" {
		e.Event = "Выход из панели"
	}
	return e, nil
}
