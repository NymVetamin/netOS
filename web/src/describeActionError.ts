export type ActionErrorSummary = { title: string; reason: string; hint: string; context?: string };

// Older servers return a single diagnostic string. Recognize explicit causes,
// keep the original intact for details, and never guess from an exit code alone.
export function describeActionError(raw: string): ActionErrorSummary {
  const component = raw.match(/не удалось изменить компоненты:\s*([^:\n]{1,160}):/i)?.[1];
  const context = component ? `Компонент: ${component}` : undefined;
  const packages = /apt-get|dpkg|установка пакетов/i.test(raw);
  const title = packages ? "Не удалось установить пакеты" : "Не удалось выполнить действие";
  if (/откат[^.\n]*(?:не удал(?:ось|ся)|ошибк)|не удалось (?:откатить|восстановить)|rollback failed/i.test(raw)) {
    return { title: "Не удалось восстановить прежние настройки", reason: "При откате произошла ошибка. Состояние системы требует проверки.", hint: "Проверьте состояние служб и журнал перед повторным применением.", context };
  }
  if (/temporary failure (?:in name resolution|resolving)|could not resolve|name or service not known|no such host/i.test(raw)) {
    return { title, reason: packages ? "Роутер не может определить адрес сервера пакетов: ошибка DNS." : "Не удалось определить адрес сервера: ошибка DNS.", hint: "Проверьте DNS и доступ роутера в интернет, затем повторите действие.", context };
  }
  if (/could not get lock|unable to acquire.*lock|dpkg.*locked|блокировк.*(?:apt|dpkg)/i.test(raw)) {
    return { title, reason: "Менеджер пакетов занят другой установкой или обновлением.", hint: "Дождитесь завершения другой операции и повторите действие.", context };
  }
  if (/no space left on device|недостаточно места/i.test(raw)) {
    return { title, reason: "На диске недостаточно свободного места.", hint: "Проверьте заполнение диска и освободите место перед повторной попыткой.", context };
  }
  if (/certificate verification failed|certificate verify failed|certificate has expired/i.test(raw)) {
    return { title, reason: "Не удалось проверить сертификат сервера.", hint: "Проверьте дату и время роутера и настройки доверенных сертификатов.", context };
  }
  if (/network is unreachable|no route to host|connection timed out|connection refused|failed to fetch/i.test(raw)) {
    return { title, reason: "Не удалось подключиться к серверу или загрузить необходимые файлы.", hint: "Проверьте подключение, маршрут и доступность сервера, затем повторите действие.", context };
  }
  return { title, reason: "Операция завершилась с ошибкой.", hint: "Откройте технические подробности, чтобы уточнить причину. При обращении за помощью приложите этот текст.", context };
}
