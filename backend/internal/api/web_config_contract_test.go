package api

import (
	"io/fs"
	"strings"
	"testing"
)

// Supported configuration must not silently become API-only again. This is
// intentionally checked against the embedded production bundle: a source-only
// editor that was not rebuilt is just as unavailable to an installed router as
// a missing editor.
func TestEmbeddedPanelExposesSupportedConfigFieldsAndPlan(t *testing.T) {
	bundle, err := fs.ReadFile(webFS, "webdist/app.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(bundle)
	for _, label := range []string{
		"MAC интерфейса",
		"Комментарий устройства",
		"Все условия и служебные поля",
		"MAC источника",
		"Сегмент-источник",
		"Входящий VPN-сервер",
		"VPN-пир",
		"Ограничить расписанием",
		"Диагностика Reality",
		"Включить show",
		"Показать план",
		"Свой сертификат и ключ",
		"Автоматический сертификат ACME",
		"Публичное имя панели",
		"Email для уведомлений ACME",
		"router.your-domain.com",
		"Принимаю действующие условия",
		"Сменить порт / TLS",
		"автоматическим возвратом",
		"DNS blocklists",
		"HTTPS URL списка",
		"Добавить DNS blocklist",
		"Домены политики",
	} {
		if !strings.Contains(text, label) {
			t.Errorf("production panel does not expose %q", label)
		}
	}
}
