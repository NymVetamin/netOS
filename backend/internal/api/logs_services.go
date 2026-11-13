package api

import (
	"sort"
	"strconv"
	"strings"
)

// Stable systemd MESSAGE_ID values, independent of the manager's locale.
// UNIT_STARTED describes a completed start job, not the current unit state.
var serviceEvents = map[string]string{
	"7d4958e842da4a758f6c1cdc7b36dcc5": "Запуск службы",
	"39f53479d3a045ac8e11786248231fbf": "Служба запущена",
	"be02cf6855d2428ba40df7e9d022f03d": "Не удалось запустить службу",
	"de5b426a63be47a7b6ac3eaac82e2f6f": "Остановка службы",
	"9d1aaa27d60140bd96365438aad20286": "Служба остановлена",
	"d34d037fff1847e6ae669a370e694725": "Перечитывание настроек",
	"7b05ebc668384222baa8881179cfda54": "Настройки перечитаны",
	"5eb03494b6584870a536b337290809b3": "Запланирован перезапуск",
	"7ad2d189f7e94e70a38c781354912448": "Служба завершилась",
	"0e4284a0caca4bfc81c0bb6786972673": "Запуск пропущен по условию",
	"d9b373ed55a64feb8242e02dbe79a49c": "Служба перешла в ошибку",
	"98e322203f7a4ed290d09fe03c09fe15": "Процесс службы завершился",
}

func serviceJournalMatches() []string {
	args := []string{"-u", "netos*.service", "_PID=1"}
	ids := make([]string, 0, len(serviceEvents))
	for id := range serviceEvents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		args = append(args, "MESSAGE_ID="+id)
	}
	return append(args, "+", "PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3", "PRIORITY=4")
}

func serviceLogFields(field func(string) string, message string) (unit, event, severity string, keep bool) {
	unit = field("_SYSTEMD_UNIT")
	priority, err := strconv.Atoi(field("PRIORITY"))
	severity = "info"
	if err == nil && priority >= 0 && priority <= 3 {
		severity = "error"
	} else if priority == 4 && err == nil {
		severity = "warning"
	}
	if field("_PID") == "1" {
		if target := field("UNIT"); target != "" {
			unit = target
		}
		event = serviceEvents[field("MESSAGE_ID")]
	}
	// Existing netosd versions print their level into stderr, which journald
	// may store at info priority. Retain those warnings without changing logging.
	if unit == "netosd.service" {
		if strings.Contains(message, "[ошиб]") {
			severity = "error"
		} else if strings.Contains(message, "[пред]") {
			severity = "warning"
		}
	}
	keep = event != "" || severity != "info"
	if event == "" && keep {
		if severity == "error" {
			event = "Ошибка службы"
		} else {
			event = "Предупреждение службы"
		}
	}
	return
}
