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

const NAV: { group: string; items: { id: PageID; label: string; icon: string }[] }[] = [
  {
    group: "Обзор",
    items: [
      { id: "dashboard", label: "Сводка", icon: "◉" },
      { id: "clients", label: "Клиенты", icon: "▪" },
    ],
  },
  {
    group: "Сеть",
    items: [
      { id: "network", label: "Интерфейсы и сегменты", icon: "⇄" },
      { id: "routing", label: "Маршрутизация", icon: "⤳" },
      { id: "channels", label: "Каналы и политики", icon: "◇" },
      { id: "vpn-servers", label: "VPN-серверы", icon: "⌁" },
      { id: "wifi", label: "Wi-Fi", icon: "⌁" },
      { id: "traffic", label: "Трафик и QoS", icon: "≋" },
      { id: "firewall", label: "Файрволл", icon: "▣" },
      { id: "services", label: "DHCP и DNS", icon: "⌘" },
    ],
  },
  {
    group: "Роутер",
    items: [
      { id: "components", label: "Компоненты", icon: "⊞" },
      { id: "system", label: "Система", icon: "⚙" },
    ],
  },
  {
    group: "Служебное",
    items: [
      { id: "history", label: "История", icon: "↺" },
      { id: "diagnostics", label: "Диагностика", icon: "✽" },
    ],
  },
];

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
            {mobileNavOpen ? "×" : "☰"}
          </button>
        </div>

        <nav className="nav">
          {NAV.map((group) => (
            <div key={group.group}>
              <div className="nav-group-title">{group.group}</div>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={`nav-item ${page === item.id ? "active" : ""}`}
                  onClick={() => {
                    setPage(item.id);
                    setMobileNavOpen(false);
                  }}
                >
                  <span className="icon" aria-hidden="true">
                    {item.icon}
                  </span>
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
              title="Тема оформления"
              onClick={() =>
                setTheme(theme === "dark" ? "light" : theme === "light" ? "auto" : "dark")
              }
            >
              {theme === "dark" ? "☾" : theme === "light" ? "☀" : "◐"}
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
                <SystemPage config={cfg} patch={patch} session={session} />
              )}
              {page === "history" && <HistoryPage onRestored={reload} />}
              {page === "diagnostics" && <DiagnosticsPage />}
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
