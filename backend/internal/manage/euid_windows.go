//go:build windows

package manage

// Управление установленной системой поддерживается только на Linux. Значение
// оставляет изменяющие команды заблокированными при локальном запуске в Windows.
func effectiveUID() int { return -1 }
