package system

import "strings"

// routeStateFlags — флаги, которые `ip route show` печатает, а `ip route
// add/replace/del` отвергает («"linkdown" is garbage»; сверено с iproute2 6.15).
// onlink сюда не входит: его iproute2 принимает и на входе.
var routeStateFlags = map[string]bool{
	"linkdown": true, "dead": true, "pervasive": true, "offload": true, "trap": true,
	"notify": true, "unresolved": true, "rt_offload": true, "rt_trap": true, "rt_offload_failed": true,
}

// ReplayableRouteFields разбивает строку `ip route show` на поля, пригодные для
// повтора в `ip route`. Аплинк без кабеля печатается с linkdown, и повтор такой
// строки как есть откатывал всё применение.
func ReplayableRouteFields(line string) []string {
	fields := strings.Fields(line)
	result := fields[:0]
	prev := ""
	for _, field := range fields {
		// Имена после dev, table и proto задаёт администратор: мост trap — не флаг.
		named := prev == "dev" || prev == "table" || prev == "proto"
		if named || !routeStateFlags[field] {
			result = append(result, field)
		}
		prev = field
	}
	return result
}
