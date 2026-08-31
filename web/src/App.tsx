import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, ConfigResponse, Problem, Session } from "./api";
import { Notice, Spinner } from "./ui";
import { Dashboard } from "./pages/Dashboard";
import { Clients } from "./pages/Clients";
import { NetworkPage } from "./pages/Network";
import { RoutingPage } from "./pages/Routing";
import { ServicesPage } from "./pages/Services";
import { FirewallPage } from "./pages/Firewall";
import { ComponentsPage } from "./pages/Components";
import { SystemPage } from "./pages/System";
import { HistoryPage } from "./pages/History";
import { DiagnosticsPage } from "./pages/Diagnostics";
import { ChannelsPage } from "./pages/Channels";
import { VPNServersPage } from "./pages/VPNServers";
import { WiFiPage } from "./pages/WiFi";
import { TrafficPage } from "./pages/Traffic";

type PageID =
  | "dashboard"
  | "clients"
  | "network"
  | "routing"
  | "channels"
  | "vpn-servers"
  | "wifi"
  | "traffic"
  | "services"
  | "firewall"
  | "components"
  | "system"
  | "history"
  | "diagnostics";

type IconName = "dashboard" | "clients" | "network" | "routing" | "channels" | "vpn" | "wifi" | "traffic" | "firewall" | "services" | "components" | "system" | "history" | "diagnostics";

const NAV: { group: string; items: { id: PageID; label: string; icon: IconName }[] }[] = [
  {
    group: "Обзор",
    items: [
      { id: "dashboard", label: "Сводка", icon: "dashboard" },
      { id: "clients", label: "Устройства", icon: "clients" },
    ],
  },
  {
    group: "Сеть",
    items: [
      { id: "network", label: "Сеть", icon: "network" },
      { id: "routing", label: "Маршрутизация", icon: "routing" },
      { id: "channels", label: "Интернет-каналы", icon: "channels" },
      { id: "vpn-servers", label: "VPN-доступ", icon: "vpn" },
      { id: "wifi", label: "Wi-Fi", icon: "wifi" },
      { id: "traffic", label: "Скорость и QoS", icon: "traffic" },
      { id: "firewall", label: "Защита сети", icon: "firewall" },
      { id: "services", label: "Адреса и DNS", icon: "services" },
    ],
  },
  {
    group: "Роутер",
    items: [
      { id: "components", label: "Компоненты", icon: "components" },
      { id: "system", label: "Система", icon: "system" },
    ],
  },
  {
    group: "Служебное",
    items: [
      { id: "history", label: "История", icon: "history" },
      { id: "diagnostics", label: "Диагностика", icon: "diagnostics" },
    ],
  },
];

const ICON_PATHS: Record<IconName, React.ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
  clients: <><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></>,
  network: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/><path d="M10 6.5h4a3.5 3.5 0 0 1 3.5 3.5v4M14 17.5h-4A3.5 3.5 0 0 1 6.5 14v-4"/></>,
  routing: <><circle cx="6" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><path d="M8.5 16.5 15.5 8.5M9 6h3a6 6 0 0 1 6 6v3"/></>,
  channels: <><path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="2.5"/><circle cx="16" cy="17" r="2.5"/></>,
  vpn: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
  wifi: <><path d="M5 12.55a11 11 0 0 1 14 0M8.5 16a6 6 0 0 1 7 0M12 20h.01M2 9a16 16 0 0 1 20 0"/></>,
  traffic: <><path d="M7 3v18M17 21V3M3 7l4-4 4 4M13 17l4 4 4-4"/></>,
  firewall: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10ZM8 12h8M12 8v8"/>,
  services: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21h-4v-.09A1.7 1.7 0 0 0 8.6 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1.1-.4H3v-4h.09A1.7 1.7 0 0 0 4.6 8.6a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1.1V3h4v.09A1.7 1.7 0 0 0 15.4 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.4 9c.14.38.35.72.6 1 .3.28.69.43 1.1.4H21v4h-.09a1.7 1.7 0 0 0-1.51.6Z"/></>,
  components: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M17.5 14v7M14 17.5h7"/></>,
  system: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l-2.86 2.86A1.7 1.7 0 0 0 15 19.4 1.7 1.7 0 0 0 13.6 21h-3.2A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.88.34l-2.86-2.86A1.7 1.7 0 0 0 4.6 15 1.7 1.7 0 0 0 3 13.6v-3.2A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.88l2.86-2.86A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10.4 3h3.2A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.88-.34l2.86 2.86A1.7 1.7 0 0 0 19.4 9 1.7 1.7 0 0 0 21 10.4v3.2A1.7 1.7 0 0 0 19.4 15Z"/></>,
  history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></>,
  diagnostics: <><path d="M4 19v-4M8 19V9M12 19v-7M16 19V5M20 19v-9"/><path d="m3 6 4 2 4-4 4 2 6-4"/></>,
};

function NavIcon({ name }: { name: IconName }) {
  return <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{ICON_PATHS[name]}</svg>;
}

function MenuIcon({ close }: { close: boolean }) {
  return <svg className="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">{close ? <><path d="m6 6 12 12"/><path d="M18 6 6 18"/></> : <><path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/></>}</svg>;
}

function ThemeIcon({ theme }: { theme: string }) {
  return <svg className="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{theme === "dark" ? <path d="M21 12.8A8.5 8.5 0 1 1 11.2 3 6.7 6.7 0 0 0 21 12.8Z"/> : theme === "light" ? <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.41M17.66 6.34l1.41-1.41"/></> : <><circle cx="12" cy="12" r="8"/><path d="M12 4v16a8 8 0 0 0 0-16Z"/></>}</svg>;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    // Cookie сессии переживает перезагрузку страницы, а CSRF-токен живёт
    // только в памяти. Поэтому при старте всегда спрашиваем сервер.
    api
      .session()
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setChecking(false));
  }, []);

  if (checking) {
    return (
      <div className="login-screen">
        <Spinner />
      </div>
    );
  }

  if (!session || !api.hasToken()) {
    return <Login onSuccess={setSession} />;
  }

  return <Shell session={session} onLogout={() => setSession(null)} />;
}

// ---------------------------------------------------------------------------
// Вход
// ---------------------------------------------------------------------------

function Login({ onSuccess }: { onSuccess: (s: Session) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onSuccess(await api.login(username, password));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Не удалось войти");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <span className="mark">nO</span>
          <div>
            <h1 style={{ fontSize: 17 }}>netOS</h1>
            <div className="faint" style={{ fontSize: 12 }}>
              панель управления роутером
            </div>
          </div>
        </div>

        <div style={{ height: "1.2rem" }} />

        <div className="field">
          <label htmlFor="u">Пользователь</label>
          <input
            id="u"
            type="text"
            value={username}
            autoComplete="username"
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="p">Пароль</label>
          <input
            id="p"
            type="password"
            value={password}
            autoComplete="current-password"
            autoFocus
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {error && (
          <div style={{ marginBottom: "0.9rem" }}>
            <Notice tone="danger" title={error} />
          </div>
        )}

        <button className="btn primary" style={{ width: "100%" }} disabled={busy || !password}>
          {busy ? "Проверяю…" : "Войти"}
        </button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Каркас
// ---------------------------------------------------------------------------

// Правки конфигурации живут в состоянии браузера и уходят на сервер с
// задержкой. Иначе каждое нажатие клавиши приводило бы к запросу, а ответ
// подменял бы объект конфигурации прямо под курсором — поле теряло фокус и
// текст не набирался.
const SAVE_DELAY_MS = 500;

function Shell({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const [page, setPage] = useState<PageID>("dashboard");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [cfg, setCfg] = useState<any>(null);
  const [problems, setProblems] = useState<Problem[]>([]);
  const [dirty, setDirty] = useState(false);
  const [pending, setPending] = useState<{ until?: string } | null>(null);
  const [rollback, setRollback] = useState<any>(null);
  const [saveError, setSaveError] = useState("");
  const [theme, setTheme] = useState<string>(
    () => localStorage.getItem("netos-theme") || "auto",
  );

  const saveTimer = useRef<number | undefined>(undefined);
  const pendingCfg = useRef<any>(null);
  // PUT-запросы выполняются строго по очереди: более старый ответ не должен
  // перезаписать на сервере конфигурацию, отправленную позже.
  const saveChain = useRef<Promise<void>>(Promise.resolve());

  const applyServerState = useCallback((res: ConfigResponse) => {
    setCfg(res.config);
    setProblems(res.problems || []);
    setDirty(res.dirty);
    setRollback(res.rollback || null);
    setPending(res.pending_confirmation ? { until: res.confirm_deadline } : null);
  }, []);

  const reload = useCallback(async () => {
    try {
      applyServerState(await api.getConfig());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onLogout();
    }
  }, [applyServerState, onLogout]);

  useEffect(() => {
    reload();
  }, [reload]);

  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("netos-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [mobileNavOpen]);

  // flush отправляет накопленные правки. Ответ обновляет только список
  // замечаний: сама конфигурация остаётся той, что в браузере, иначе текст,
  // набранный за время запроса, потерялся бы.
  const flush = useCallback(async () => {
    const next = pendingCfg.current;
    if (!next) return;
    pendingCfg.current = null;

    const job = saveChain.current.then(async () => {
      try {
        const res = await api.saveConfig(next);
        setProblems(res.problems || []);
        // Черновик, совпавший с применённой конфигурацией, черновиком быть
        // перестаёт: сервер отвечает dirty=false, и полоса применения уходит
        // сама. Иначе правка, возвращённая к исходному значению, до конца
        // сеанса предлагала бы применить пустоту.
        setDirty(res.dirty);
        setSaveError("");
      } catch (err) {
        if (err instanceof ApiError) {
          setProblems(err.problems || []);
          setSaveError(err.problems?.length ? "" : err.message);
          setDirty(true);
        }
        if (!pendingCfg.current) pendingCfg.current = next;
        throw err;
      }
    });
    saveChain.current = job.catch(() => {});
    await job;
  }, []);

  // patch — единственный способ изменить конфигурацию. Мутатор получает копию
  // текущего дерева, изменения сразу видны в интерфейсе.
  const patch = useCallback(
    (mutate: (draft: any) => void) => {
      if (session.role !== "admin") return;
      setCfg((current: any) => {
        if (!current) return current;
        const next = structuredClone(current);
        mutate(next);
        pendingCfg.current = next;
        window.clearTimeout(saveTimer.current);
        saveTimer.current = window.setTimeout(() => {
          void flush().catch(() => {});
        }, SAVE_DELAY_MS);
        return next;
      });
    },
    [flush, session.role],
  );

  // Перед применением сбрасываем то, что ещё не ушло на сервер.
  const flushNow = useCallback(async () => {
    window.clearTimeout(saveTimer.current);
    // Пока ожидали предыдущую запись, пользователь мог успеть внести ещё одну
    // правку. Перед Apply выгребаем очередь полностью.
    do {
      await flush();
    } while (pendingCfg.current);
    await saveChain.current;
  }, [flush]);

  const errors = problems.filter((p) => p.severity === "error");

  return (
    <div className="shell">
      <aside className={`sidebar ${mobileNavOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-head">
          <span className="mark">nO</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 600 }}>netOS</div>
            <div className="host">{cfg?.system?.hostname || "…"}</div>
          </div>
          <button
            type="button"
            className="btn ghost mobile-nav-toggle"
            aria-label={mobileNavOpen ? "Закрыть меню" : "Открыть меню"}
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <MenuIcon close={mobileNavOpen} />
          </button>
        </div>

        <nav className="nav">
          {NAV.map((group) => ({
            ...group,
            // Rendered service configurations can contain private keys and
            // credentials. The API correctly keeps them admin-only, so do not
            // offer a viewer a page that can only end in 403.
            items: group.items.filter((item) => session.role === "admin" || item.id !== "diagnostics"),
          })).filter((group) => group.items.length > 0).map((group) => (
            <div key={group.group}>
              <div className="nav-group-title">{group.group}</div>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={`nav-item ${page === item.id ? "active" : ""}`}
                  aria-label={item.label}
                  aria-current={page === item.id ? "page" : undefined}
                  onClick={() => {
                    setPage(item.id);
                    setMobileNavOpen(false);
                  }}
                >
                  <span className="icon"><NavIcon name={item.icon} /></span>
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <span className="faint" style={{ fontSize: 12 }}>
            {session.username}
          </span>
          <div className="row" style={{ gap: "0.25rem" }}>
            <button
              className="btn ghost sm"
              aria-label={`Тема оформления: ${theme === "dark" ? "тёмная" : theme === "light" ? "светлая" : "системная"}`}
              title="Сменить тему оформления"
              onClick={() =>
                setTheme(theme === "dark" ? "light" : theme === "light" ? "auto" : "dark")
              }
            >
              <ThemeIcon theme={theme} />
            </button>
            <button
              className="btn ghost sm"
              onClick={async () => {
                await api.logout();
                onLogout();
              }}
            >
              Выйти
            </button>
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="page">
          {session.role !== "admin" && (
            <Notice tone="info" title="Режим просмотра">
              Изменение конфигурации для этой учётной записи запрещено.
            </Notice>
          )}

          {rollback && (
            <Notice
              tone="danger"
              title={
                rollback.reason === "timeout"
                  ? "Изменения откачены: подтверждение не получено"
                  : "Изменения откачены"
              }
            >
              Ревизия {rollback.revision} не подтверждена, роутер вернулся к предыдущей
              конфигурации. {rollback.details}
            </Notice>
          )}

          {saveError && (
            <Notice tone="danger" title="Не удалось сохранить черновик">
              {saveError}
            </Notice>
          )}

          {!cfg ? (
            <Spinner />
          ) : (
            <>
              {page === "dashboard" && <Dashboard config={cfg} />}
              {page === "clients" && <Clients config={cfg} patch={patch} />}
              {page === "network" && (
                <NetworkPage config={cfg} patch={patch} problems={problems} />
              )}
              {page === "routing" && <RoutingPage config={cfg} patch={patch} />}
              {page === "channels" && <ChannelsPage config={cfg} patch={patch} />}
              {page === "vpn-servers" && <VPNServersPage config={cfg} patch={patch} />}
              {page === "wifi" && <WiFiPage config={cfg} patch={patch} />}
              {page === "traffic" && <TrafficPage config={cfg} patch={patch} />}
              {page === "services" && <ServicesPage config={cfg} patch={patch} />}
              {page === "firewall" && <FirewallPage config={cfg} patch={patch} />}
              {page === "components" && <ComponentsPage config={cfg} patch={patch} />}
              {page === "system" && (
                <SystemPage config={cfg} patch={patch} session={session} onSessionEnded={onLogout} />
              )}
              {page === "history" && <HistoryPage onRestored={reload} />}
              {page === "diagnostics" && session.role === "admin" && <DiagnosticsPage />}
            </>
          )}
        </div>
      </main>

      {session.role === "admin" && (
        <ApplyBar
          dirty={dirty}
          pending={pending}
          errorCount={errors.length}
          onFlush={flushNow}
          onReload={reload}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Панель применения
// ---------------------------------------------------------------------------

function ApplyBar({
  dirty,
  pending,
  errorCount,
  onFlush,
  onReload,
}: {
  dirty: boolean;
  pending: { until?: string } | null;
  errorCount: number;
  onFlush: () => Promise<void>;
  onReload: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [remaining, setRemaining] = useState(0);
  const timerRef = useRef<number | undefined>(undefined);

  // Обратный отсчёт до автоматического отката держим на виду: именно в эти
  // секунды администратор обязан проверить, что связь не потеряна.
  useEffect(() => {
    window.clearInterval(timerRef.current);
    if (!pending?.until) {
      setRemaining(0);
      return;
    }
    const deadline = new Date(pending.until).getTime();
    const tick = () => {
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      setRemaining(left);
      if (left === 0) {
        window.clearInterval(timerRef.current);
        onReload();
      }
    };
    tick();
    timerRef.current = window.setInterval(tick, 1000);
    return () => window.clearInterval(timerRef.current);
  }, [pending, onReload]);

  if (pending) {
    return (
      <div className="applybar">
        <div className="msg">
          <strong>Подтвердите изменения</strong>
          <div className="dim">
            Если связь с роутером потеряна, ничего не нажимайте — конфигурация вернётся
            автоматически через <span className="countdown">{remaining}</span> с.
          </div>
        </div>
        <div className="actions">
          <button
            className="btn"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.rollback();
                onReload();
              } finally {
                setBusy(false);
              }
            }}
          >
            Откатить
          </button>
          <button
            className="btn primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.confirm();
                onReload();
              } finally {
                setBusy(false);
              }
            }}
          >
            Всё работает
          </button>
        </div>
      </div>
    );
  }

  if (!dirty) return null;

  return (
    <div className="applybar">
      <div className="msg">
        <strong>Есть несохранённые изменения</strong>
        <div className="dim">
          {errorCount > 0 ? (
            <span style={{ color: "var(--danger)" }}>
              Ошибок в конфигурации: {errorCount} — исправьте перед применением
            </span>
          ) : error ? (
            <span style={{ color: "var(--danger)" }}>{error}</span>
          ) : (
            "Изменения вступят в силу сразу, перезагрузка не нужна."
          )}
        </div>
      </div>
      <div className="actions">
        <button
          className="btn ghost"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await api.discardDraft();
              onReload();
            } finally {
              setBusy(false);
            }
          }}
        >
          Отменить
        </button>
        <button
          className="btn primary"
          disabled={busy || errorCount > 0}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await onFlush();
              await api.apply("изменения из панели");
              onReload();
            } catch (err) {
              setError(err instanceof ApiError ? err.message : "Применение не удалось");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Применяю…" : "Применить"}
        </button>
      </div>
    </div>
  );
}
