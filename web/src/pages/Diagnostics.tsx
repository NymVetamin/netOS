import { LogEntries } from "./Logs";
import { DiagnosticTool, DIAGNOSTIC_TOOLS } from "./DiagnosticTool";
import { useEffect, useState, ReactNode } from "react";
import { api } from "../api";
import { Card, Empty, Notice, TableWrap } from "../ui";
import { Icon } from "../icons";

// Диагностика показывает, во что превратилась конфигурация: настоящие правила
// iptables, конфиги работающих демонов, таблицу маршрутов. Администратор
// должен иметь возможность проверить работу панели, а не верить ей на слово.
//
// Список конфигов приходит с сервера и зависит от выбранных демонов. Зашитый в
// панели перечень показывал конфигурацию dnsmasq всегда — в том числе когда
// dnsmasq выключен, а работают unbound и ISC DHCP, конфигов которых не было
// видно вовсе.
const ROUTES = "netos:routes";
const NEIGHBORS = "netos:neighbors";

const DIAGNOSTIC_TABS = [
  ...DIAGNOSTIC_TOOLS.map(t => ({id: t.id, label: t.label})),
  {id: "state", label: "Маршруты и соседи"},
  {id: "logs", label: "Журналы"},
  {id: "configs", label: "Конфиги"},
];
let lastDiagnosticTab = "ping";
function diagnosticTabFromHash() {
  const query = new URLSearchParams(window.location.hash.split("?")[1] || "");
  const value = query.get("tab") || (query.has("log") ? "logs" : "");
  lastDiagnosticTab = DIAGNOSTIC_TABS.some(t => t.id === value) ? value : lastDiagnosticTab;
  return lastDiagnosticTab;
}
export function DiagnosticsPage({ admin = true, dnsLogging = false }: { admin?: boolean; dnsLogging?: boolean }) {
  const [selected, setSelected] = useState(diagnosticTabFromHash);
  const tab = selected === "configs" && !admin ? "state" : selected;
  const [tools, setTools] = useState<Awaited<ReturnType<typeof api.diagnosticTools>> | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const follow = () => setSelected(diagnosticTabFromHash());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  useEffect(() => {
    let cancelled = false;
    setError("");
    api.diagnosticTools().then(value => { if (!cancelled) setTools(value); })
      .catch(e => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [attempt]);
  const tool = DIAGNOSTIC_TOOLS.find(t => t.id === tab);
  return <>
    <div className="page-head"><h1><Icon name="activity" />Диагностика</h1><p>Проверка сети и трафика с самого роутера</p></div>
    <div role="tablist" aria-label="Диагностика" className="row wrap service-tabs">
      {DIAGNOSTIC_TABS.filter(t => admin || t.id !== "configs").map(t => <a key={t.id} role="tab" id={`diagnostic-tab-${t.id}`} aria-controls={`diagnostic-${t.id}`} aria-selected={tab === t.id} className={`btn sm ${tab === t.id ? "primary" : ""}`} href={`#diagnostics?tab=${t.id}`}>{t.label}</a>)}
    </div>
    <div role="tabpanel" id={`diagnostic-${tab}`} aria-labelledby={`diagnostic-tab-${tab}`}>
      {tool && <>
        {error && <Notice tone="danger" title="Не удалось проверить инструменты">{error} <button className="btn sm" onClick={() => setAttempt(n => n + 1)}>Повторить</button></Notice>}
        {!tools && !error && <Empty>Проверка инструментов…</Empty>}
        {tools && <DiagnosticTool key={tab} tool={tool} capabilities={tools} refresh={() => setAttempt(n => n + 1)} />}
      </>}
      {tab === "logs" && <LogEntries dnsLogging={dnsLogging} />}
      {(tab === "state" || tab === "configs") && <DiagnosticArtifacts key={tab} admin={admin} mode={tab} />}
    </div>
  </>;
}

function DiagnosticArtifacts({ admin, mode }: { admin: boolean; mode: "state" | "configs" }) {
  const [artifacts, setArtifacts] = useState<{ id: string; title: string }[]>([]);
  // Вкладка пуста, пока не пришёл список: открывать что-то до него значило бы
  // сходить на сервер дважды и показать не то, что откроется в итоге.
  const [tab, setTab] = useState<string>("");
  const [content, setContent] = useState("");
  const [arp, setArp] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadedTab, setLoadedTab] = useState("");
  const [error, setError] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [listAttempt, setListAttempt] = useState(0);
  const [refreshVersion, setRefreshVersion] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setListLoading(true);
    setListError("");
    (async () => {
      try {
        const list = admin && mode === "configs" ? await api.renderList() : [];
        if (cancelled) return;
        setArtifacts(list);
        // Первым открывается первый же артефакт — им всегда оказывается то, что
        // определяет доступность машины: правила iptables.
        setTab(previous => list.some(item => item.id === previous) ? previous : list.length > 0 ? list[0].id : mode === "state" ? ROUTES : "");
      } catch (cause) {
        if (!cancelled) {
          setListError(cause instanceof Error ? cause.message : "Не удалось загрузить список диагностики");
          setTab(mode === "state" ? ROUTES : "");
        }
      } finally {
        if (!cancelled) setListLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [listAttempt, admin, mode]);

  useEffect(() => {
    if (!tab) return;
    let cancelled = false;
    setLoading(true);
    setError("");
    (async () => {
      try {
        if (tab === ROUTES) {
          const r = await api.routes();
          if (!cancelled) {
            setContent(
              "# таблица маршрутов\n" + r.routes + "\n# правила выбора таблиц\n" + r.rules,
            );
            setLoadedTab(tab);
          }
        } else if (tab === NEIGHBORS) {
          const r = await api.arp();
          if (!cancelled) {
            setArp(r.arp || []);
            setLoadedTab(tab);
          }
        } else {
          const text = await api.render(tab);
          if (!cancelled) {
            setContent(text);
            setLoadedTab(tab);
          }
        }
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Не удалось загрузить диагностику");
          setLoadedTab(tab);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshVersion]);

  const tabs = [
    ...(mode === "configs" ? artifacts : [
      { id: ROUTES, title: "Маршруты" },
      { id: NEIGHBORS, title: "Таблица соседей" },
    ]),
  ];

  const selectTab = (id: string) => {
    if (id === tab) return;
    // React applies both changes in one update, so stale content cannot appear
    // under the next tab's title even when the request is slow.
    setLoading(true);
    setError("");
    setCopyStatus("");
    setTab(id);
  };

  const pending = listLoading || loading || loadedTab !== tab;

  async function copyContent() {
    setCopyStatus("");
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(content);
      } else {
        throw new Error("Clipboard API недоступен");
      }
      setCopyStatus("Скопировано");
    } catch {
      const area = document.createElement("textarea");
      area.value = content;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand("copy");
      area.remove();
      setCopyStatus(copied ? "Скопировано" : "Не удалось скопировать");
    }
  }

  return (
    <>
      {listLoading && <Empty>Загрузка списка диагностики…</Empty>}
      {listError && (
        <Notice tone="danger" title="Не удалось загрузить список диагностики">
          <p>{listError}</p>
          <button className="btn sm" onClick={() => setListAttempt((attempt) => attempt + 1)}>
            Повторить загрузку
          </button>
        </Notice>
      )}

      <div className="row wrap" style={{ marginBottom: "1rem", gap: "0.4rem" }}>
        <button className="btn sm" disabled={pending || !tab} onClick={() => setRefreshVersion(n => n + 1)}>Обновить</button>
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`btn sm ${tab === t.id ? "primary" : ""}`}
            onClick={() => selectTab(t.id)}
          >
            {t.title}
          </button>
        ))}
      </div>

      {!tab ? (!listLoading && !listError && <Empty>Доступных конфигов нет</Empty>) : tab === NEIGHBORS ? (
        <Card title="Таблица соседей" tight>
          {pending ? (
            <Empty>Загрузка…</Empty>
          ) : error ? (
            <Empty>{error}</Empty>
          ) : arp.length === 0 ? (
            <Empty>Записей нет</Empty>
          ) : (
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th>Адрес</th>
                    <th>MAC</th>
                    <th>Интерфейс</th>
                    <th>Состояние</th>
                  </tr>
                </thead>
                <tbody>
                  {arp.map((e, i) => (
                    <tr key={i}>
                      <td className="mono">{e.ip}</td>
                      <td className="mono faint">{e.mac}</td>
                      <td className="mono">{e.interface}</td>
                      <td className="faint">{e.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      ) : (
        <div className="card">
          <div className="card-head">
            <div>
              <h2>{tabs.find((t) => t.id === tab)?.title}</h2>
              <div className="sub">
                {tab === ROUTES ? "Снято с живой системы" : "Сгенерировано из текущей конфигурации. Секреты скрыты."}
              </div>
            </div>
            <button className="btn sm" onClick={copyContent} disabled={pending || !!error}>
              {copyStatus || "Скопировать"}
            </button>
          </div>
          <pre className="output">{pending ? "Загрузка…" : error || <Highlight text={content} />}</pre>
        </div>
      )}
    </>
  );
}

// Подсветка сгенерированных конфигов: комментарии, заголовки разделов, строки
// в кавычках, флаги, адреса и вердикты файрволла. Текст не меняется — копируется
// исходный. Разбор построчный и общий для всех артефактов: это не парсер
// формата, а помощь глазу.
const TOKEN = /(")|((?<![\w.-])-{1,2}[A-Za-z][\w-]*)|((?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?(?![\w.]))|(\b(?:ACCEPT|MASQUERADE)\b)|(\b(?:DROP|REJECT)\b)/g;

function Highlight({ text }: { text: string }) {
  return <>{text.split("\n").map((line, n) => {
    const trimmed = line.trimStart();
    if (/^[#;]/.test(trimmed)) return <span key={n} className="hl-comment">{line}{"\n"}</span>;
    if (/^(\[.*\]|\*\w+|COMMIT)$/.test(trimmed)) return <span key={n} className="hl-head">{line}{"\n"}</span>;
    const parts: ReactNode[] = [];
    let last = 0;
    let unclosedUntil = 0;
    TOKEN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = TOKEN.exec(line)) !== null) {
      const at = match.index;
      let token = match[0];
      if (match[1]) {
        if (at < unclosedUntil) continue;
        let end = at + 1;
        for (; end < line.length; end++) {
          if (line[end] === '"') break;
          if (line[end] === '\\') {
            const escaped = line.charCodeAt(end + 1);
            if (end + 1 === line.length || escaped === 10 || escaped === 13 || escaped === 0x2028 || escaped === 0x2029) break;
            end++;
          }
        }
        if (line[end] !== '"') {
          // Quotes inside this failed scan were escaped and share its failing suffix.
          // Skip their repeated scans, but still highlight other tokens in that text.
          unclosedUntil = end + 1;
          continue;
        }
        token = line.slice(at, end + 1);
        TOKEN.lastIndex = end + 1;
      }
      parts.push(line.slice(last, at));
      parts.push(<span key={at} className={match[1] ? "hl-string" : match[2] ? "hl-flag" : match[3] ? "hl-number" : match[4] ? "hl-ok" : "hl-bad"}>{token}</span>);
      last = at + token.length;
    }
    parts.push(line.slice(last));
    return <span key={n}>{parts}{"\n"}</span>;
  })}</>;
}
