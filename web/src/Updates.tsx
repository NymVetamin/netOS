import { useEffect, useRef, useState } from "react";
import { useStatusPolling } from "./StatusPollingContext";
import { api } from "./api";
import { Notice, Field } from "./ui";

type Release = { tag_name: string; name: string; body: string; published_at: string };
export function compareVersions(a: string, b: string): number | null {
  const parse = (s: string) => /^v?\d+(\.\d+){1,3}$/.test(s) ? s.replace(/^v/, "").split(".").map(Number) : null;
  const x = parse(a), y = parse(b);
  if (!x || !y) return null;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0) ? 1 : -1;
  }
  return 0;
}

function ReleaseNotes({ release }: { release: Release }) {
  return <section className="release-notes">
    <h4>{release.name || release.tag_name}</h4>
    <p className="hint">{release.published_at ? new Date(release.published_at).toLocaleDateString("ru-RU") : ""}</p>
    {(release.body || "Автор релиза не добавил описание изменений.").split("\n").map((line, i) =>
      /^#{1,6} /.test(line) ? <h4 key={i}>{line.replace(/^#{1,6} /, "")}</h4> :
      <div key={i} style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", margin: ".3rem 0" }}>{line.replace(/^[-*] /, "• ").replace(/\*\*(.*?)\*\*/g, "$1")}</div>)}
    <a href={`https://github.com/NymVetamin/netOS/releases/tag/${encodeURIComponent(release.tag_name)}`} target="_blank" rel="noreferrer">Открыть релиз на GitHub</a>
  </section>;
}

const UPDATE_KEY = "netos-pending-update";
type PendingUpdate = { target: string; started: number };
function savedUpdate(): PendingUpdate | null {
  try { const v = JSON.parse(sessionStorage.getItem(UPDATE_KEY) || "null"); return v && typeof v.target === "string" && typeof v.started === "number" ? v : null; } catch { return null; }
}

function UpdateConfirmation({release, busy, onCancel, onConfirm}: {release: Release; busy: boolean; onCancel: () => void; onConfirm: (backup: boolean) => void}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [backup, setBackup] = useState("");
  useEffect(() => { const el = dialog.current!; el.showModal(); return () => el.close(); }, []);
  return <dialog ref={dialog} className="action-confirm update-confirm" aria-labelledby="update-confirm-title" onCancel={e => {e.preventDefault(); if (!busy) onCancel();}}>
    <h2 id="update-confirm-title">Установить {release.tag_name}?</h2>
    <p>Настройки и пользователи сохранятся. Панель временно отключится во время установки.</p>
    <Field label="Резервная копия перед обновлением"><select autoFocus aria-label="Резервная копия перед установкой" disabled={busy} value={backup} onChange={e => setBackup(e.target.value)}>
      <option value="">Выберите действие</option><option value="yes">Создать резервную копию</option><option value="no">Продолжить без копии</option>
    </select></Field>
    <div className="action-confirm-buttons"><button className="btn" disabled={busy} onClick={onCancel}>Отмена</button>
      <button className="btn primary" disabled={busy || !backup} onClick={() => onConfirm(backup === "yes")}>{busy ? "Запускаем…" : "Подтвердить установку"}</button></div>
  </dialog>;
}

export function Updates({ current, disabled, onBusyChange, onInstalled }: {
  current: string; disabled: boolean; onBusyChange: (busy: boolean) => void; onInstalled: (version: string) => void;
}) {
  const statusPolling = useStatusPolling();
  const [releases, setReleases] = useState<Release[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<Release | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [operation, setOperation] = useState<PendingUpdate | null>(savedUpdate);
  const [message, setMessage] = useState("");
  const [complete, setComplete] = useState(false);
  const progress = useRef<HTMLDivElement>(null);
  const latest = releases?.[0];
  const newer = latest && compareVersions(latest.tag_name, current);
  const developmentRelease = current === "dev" && !!latest && compareVersions(latest.tag_name, latest.tag_name) === 0;
  const active = !!operation || submitting;
  useEffect(() => { onBusyChange(active); return () => onBusyChange(false); }, [active, onBusyChange]);
  useEffect(() => {
    if (!operation) return;
    let cancelled = false, polling = false;
    let observedRunning = false;
    progress.current?.scrollIntoView({block: "nearest"});
    const finish = (text: string, failed: boolean) => {
      sessionStorage.removeItem(UPDATE_KEY); setOperation(null); setComplete(!failed);
      if (failed) {setError(text); setMessage("");} else {setMessage(text); setError("");}
    };
    const poll = async (request: Promise<any>) => {
      if (polling) return;
      polling = true;
      try {
        const [status, router] = await Promise.all([api.maintenanceStatus(), request]);
        if (cancelled) return;
        const running = status.state === "active" || status.state === "activating";
        observedRunning ||= running;
        const elapsed = Date.now() - operation.started;
        if (status.failed && (observedRunning || elapsed > 8000)) {
          finish("Обновление завершилось ошибкой. Проверьте журнал службы netos-maintenance.", true);
        } else if (!running && compareVersions(router.version || "", operation.target) === 0) {
          onInstalled(router.version);
          finish(`Обновление завершено. Установлена ${operation.target}.`, false);
        } else if (!running && (observedRunning || elapsed > 30000)) {
          finish(`Обновление не подтверждено: роутер сообщает версию ${router.version || "неизвестно"}, ожидалась ${operation.target}.`, true);
        } else {
          setMessage(status.state === "activating" ? "Обновление ожидает запуска…" : `Устанавливается ${operation.target}. Дождитесь завершения.`);
        }
      } catch {
        if (!cancelled) setMessage("Связь с панелью прервана. Ожидаем её возвращения после обновления…");
      } finally { polling = false; }
    };
    const unsubscribe = statusPolling.subscribe(2000, false, request => { void poll(request); });
    return () => {cancelled = true; unsubscribe();};
  }, [operation, statusPolling]);
  async function check() {
    setChecking(true); setError(""); setPending(null); setReleases(null);
    try { const result = await api.releases(); setReleases(result.releases || []); }
    catch (e: any) { setError(e.message || "Не удалось проверить обновления"); }
    finally { setChecking(false); }
  }
  async function install(backup: boolean) {
    if (!pending || active) return;
    setSubmitting(true); setError(""); setMessage(""); setComplete(false);
    try {
      await api.updateSystem(pending.tag_name, "UPDATE", backup);
      const next = {target: pending.tag_name, started: Date.now()};
      sessionStorage.setItem(UPDATE_KEY, JSON.stringify(next));
      setPending(null); setOperation(next); setMessage("Обновление ожидает запуска…");
    } catch (e: any) { setPending(null); setError(e.message || "Не удалось запустить обновление"); }
    finally {setSubmitting(false);}
  }
  return <>
    <h3 className="card-sub">Обновление netOS<span className="sub">Установлена версия: {current || "неизвестна"}</span></h3>
    <div className="card-part pad update-panel">
      <div className="update-toolbar">
        <button className="btn" disabled={disabled || active || checking} onClick={check}>{checking ? "Проверяем…" : "Проверить обновления"}</button>
        {latest && <span>{developmentRelease ? `Установлена тестовая сборка. Доступен релиз ${latest.tag_name}.` : newer === 1 ? `Доступна версия ${latest.tag_name}` : newer === null ? "Не удалось сравнить установленную версию с релизом." : "Новых обновлений нет."}</span>}
        {(newer === 1 || developmentRelease) && <button className="btn primary" disabled={disabled || active} onClick={() => setPending(latest!)}>{developmentRelease ? "Установить релиз" : "Обновить"}</button>}
      </div>
      <div ref={progress} className="update-status" aria-live="polite">
        {error && <Notice tone="danger" title={error} />}
        {(active || message) && <><p role="status">{message || "Запускаем обновление…"}</p>
          {(active || complete) && <progress aria-label="Прогресс обновления" {...(complete ? {value: 1, max: 1} : {})} />}
        </>}
      </div>
      {latest && <ReleaseNotes release={latest} />}
      {pending && <UpdateConfirmation release={pending} busy={submitting} onCancel={() => setPending(null)} onConfirm={backup => void install(backup)} />}
    </div>
  </>;
}
