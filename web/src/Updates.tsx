import { useState } from "react";
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

export function Updates({ current, disabled, action }: {
  current: string; disabled: boolean; action: (run: () => Promise<any>, message: string) => Promise<void>;
}) {
  const [releases, setReleases] = useState<Release[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<Release | null>(null);
  const [backup, setBackup] = useState("");
  const latest = releases?.[0];
  const newer = latest && compareVersions(latest.tag_name, current);
  async function check() {
    setChecking(true); setError(""); setPending(null); setReleases(null);
    try { const result = await api.releases(); setReleases(result.releases || []); }
    catch (e: any) { setError(e.message || "Не удалось проверить обновления"); }
    finally { setChecking(false); }
  }
  const ask = (r: Release) => { setPending(r); setBackup(""); };
  return <>
    <h3 className="card-sub">Обновление netOS<span className="sub">Установлена версия: {current || "неизвестна"}</span></h3>
    <div className="card-part pad">
      <div className="row wrap">
        <button className="btn" disabled={disabled || checking} onClick={check}>{checking ? "Проверяем…" : "Проверить обновления"}</button>
      </div>
      {error && <Notice tone="danger" title={error} />}
      {latest && <>
        <p>{newer === 1 ? `Доступна версия ${latest.tag_name}` : newer === null ? "Не удалось сравнить установленную версию с релизом." : "Новых обновлений нет."}</p>
        {newer === 1 && <button className="btn primary" disabled={disabled} onClick={() => ask(latest)}>Обновить</button>}
        <ReleaseNotes release={latest} />
      </>}
      {pending && <Notice tone="warn" title={`Установить ${pending.tag_name}?`}>
        <p>Настройки и пользователи сохранятся. Панель временно отключится во время установки. Создать резервную копию перед обновлением?</p>
        <Field label="Резервная копия"><select aria-label="Резервная копия перед установкой" value={backup} onChange={e => setBackup(e.target.value)}>
          <option value="">Выберите действие</option><option value="yes">Создать резервную копию</option><option value="no">Продолжить без копии</option>
        </select></Field>
        <div className="row wrap">
          <button className="btn primary" disabled={disabled || !backup} onClick={async () => {
            const target = pending.tag_name, makeBackup = backup === "yes";
            setPending(null);
            await action(() => api.updateSystem(target, "UPDATE", makeBackup), `Установка ${target} запланирована`);
          }}>Подтвердить установку</button>
          <button className="btn ghost" onClick={() => setPending(null)}>Отмена</button>
        </div>
      </Notice>}
    </div>
  </>;
}
