import { createContext, ReactNode, useContext, useRef, useState } from "react";
import { HintContext } from "./HintContext";
import { api, Session } from "./api";
import { Card, Notice, Switch } from "./ui";

const HintSettingsContext = createContext({ busy: false, error: "", setEnabled: (_: boolean) => {} });

export function HintProvider({ session, children }: { session: Session; children: ReactNode }) {
  const [enabled, setEnabled] = useState(session.show_hints !== false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const saving = useRef(false);
  async function save(value: boolean) {
    if (saving.current) return;
    saving.current = true;
    setBusy(true);
    setError("");
    try {
      const result = await api.setPreferences(value);
      setEnabled(result.show_hints);
    } catch (err: any) {
      setError(err?.message || "Не удалось сохранить настройку подсказок");
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  return <HintContext.Provider value={enabled}><HintSettingsContext.Provider value={{ busy, error, setEnabled: value => { void save(value); } }}>{children}</HintSettingsContext.Provider></HintContext.Provider>;
}

export function useHintPreference() {
  return { enabled: useContext(HintContext), ...useContext(HintSettingsContext) };
}

export function HintSettings() {
  const hints = useHintPreference();
  return <Card title="Подсказки" subtitle="Для вашей учётной записи. Ошибки и результаты операций остаются видимыми.">
    <Switch checked={hints.enabled} disabled={hints.busy} onChange={hints.setEnabled} label="Показывать подсказки" />
    {hints.error && <Notice tone="danger" title="Не удалось сохранить настройку подсказок">{hints.error}</Notice>}
  </Card>;
}
