package config

import (
	"strconv"
	"strings"
)

// Ссылки между интерфейсами хранятся по идентификатору, а не по имени.
//
// Имя интерфейса администратор меняет в панели в любой момент, и ссылка по
// имени пережила бы переименование только на бумаге: мост продолжал бы
// числиться с портом, которого больше нет, а VLAN — висеть на несуществующем
// родителе. Ошибка при этом молчаливая: конфигурация валидна, а в системе
// половина связей не построена. Идентификатор объекта не меняется никогда,
// поэтому связи описываются им, а имя вычисляется при генерации команд.

// InterfaceByID возвращает интерфейс по идентификатору.
func (c *Config) InterfaceByID(id string) (Interface, bool) {
	for _, i := range c.Interfaces {
		if i.ID == id {
			return i, true
		}
	}
	return Interface{}, false
}

// InterfaceName возвращает имя интерфейса по идентификатору. Для неизвестного
// идентификатора возвращается пустая строка: вызывающий обязан это проверить,
// иначе команда ip уйдёт с пустым аргументом.
func (c *Config) InterfaceName(id string) string {
	i, ok := c.InterfaceByID(id)
	if !ok {
		return ""
	}
	return i.Name
}

// InterfaceNames переводит список идентификаторов в имена, пропуская те,
// которых в конфигурации нет.
func (c *Config) InterfaceNames(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := c.InterfaceName(id); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// MasterOf возвращает мост или агрегацию, которой подчинён интерфейс.
//
// Подчинённый порт не имеет собственного адреса и не может быть ни аплинком,
// ни основанием для VLAN: весь его трафик уходит в мост. Проверка нужна и
// валидатору, и панели, поэтому живёт здесь.
func (c *Config) MasterOf(id string) (Interface, bool) {
	if id == "" {
		return Interface{}, false
	}
	for _, i := range c.Interfaces {
		if i.Type != "bridge" && i.Type != "bond" {
			continue
		}
		for _, m := range i.Members {
			if m == id {
				return i, true
			}
		}
	}
	return Interface{}, false
}

// normalizeInterfaceLinks переводит ссылки, записанные именами, в
// идентификаторы. До этой версии схемы parent и members хранили имена, и
// конфигурация с прежней установки иначе осталась бы без единой связи.
func (c *Config) normalizeInterfaceLinks() {
	ids := map[string]bool{}
	byName := map[string]string{}
	for _, i := range c.Interfaces {
		ids[i.ID] = true
		if i.Name != "" {
			byName[i.Name] = i.ID
		}
	}
	toID := func(ref string) string {
		if ref == "" || ids[ref] {
			return ref
		}
		if id, ok := byName[ref]; ok {
			return id
		}
		// Ссылка не на идентификатор и не на существующее имя. Оставляем как
		// есть: валидатор объяснит администратору, что связь оборвана, — это
		// честнее, чем молча её выбросить.
		return ref
	}

	for i := range c.Interfaces {
		c.Interfaces[i].Parent = toID(c.Interfaces[i].Parent)
		for j, m := range c.Interfaces[i].Members {
			c.Interfaces[i].Members[j] = toID(m)
		}
	}
}

// DefaultVLANName строит имя VLAN так, как его принято записывать в Linux:
// имя родителя, точка, номер. Панель предлагает его по умолчанию и
// поддерживает при смене родителя или номера, пока администратор не задал
// имя сам.
func DefaultVLANName(parentName string, vlanID int) string {
	if parentName == "" {
		return ""
	}
	name := parentName + "." + strconv.Itoa(vlanID)
	if len(name) > maxInterfaceName {
		// Ядро обрежет длинное имя молча, а на него ссылаются зоны файрволла.
		// Лучше укоротить предсказуемо здесь.
		suffix := "." + strconv.Itoa(vlanID)
		keep := maxInterfaceName - len(suffix)
		if keep < 1 {
			keep = 1
		}
		if keep > len(parentName) {
			keep = len(parentName)
		}
		name = parentName[:keep] + suffix
	}
	return name
}

// ValidInterfaceName проверяет имя на то, что ядро вообще согласится его
// принять: непустое, не длиннее IFNAMSIZ-1, без пробелов и косых черт.
func ValidInterfaceName(name string) bool {
	if name == "" || len(name) > maxInterfaceName || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, " \t/:%") {
		return false
	}
	return true
}
