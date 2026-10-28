import { PermissionContext, canAccess } from "./permissions";
import { HintProvider, HintToggle, HintSaveError } from "./HintProvider";
import { StatusPollingProvider, useStatusPolling } from "./StatusPollingContext";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { api, ApiError, ConfigResponse, formatUptime, PlanResponse, Problem, Session } from "./api";
import { PlanPreview } from "./PlanPreview";
import { Notice, Spinner } from "./ui";
import { ActionError } from "./ActionError";
import { Icon, IconName } from "./icons";
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
import { StoragePage } from "./pages/Storage";
import { TrafficPage } from "./pages/Traffic";
import { MapPage } from "./pages/Map";

type PageID =
  | "dashboard"
  | "map"
  | "clients"
  | "network"
  | "routing"
  | "channels"
  | "vpn-servers"
  | "wifi"
  | "storage"
  | "traffic"
  | "services"
  | "firewall"
  | "components"
  | "system"
  | "history"
  | "diagnostics";

const NAV: { group: string; items: { id: PageID; label: string; icon: IconName }[] }[] = [
  {
    group: "Обзор",
    items: [
      { id: "dashboard", label: "Сводка", icon: "layout-dashboard" },
      { id: "map", label: "Карта сети", icon: "waypoints" },
      { id: "clients", label: "Клиенты", icon: "users" },
    ],
  },
  {
    group: "Сеть",
    items: [
      { id: "network", label: "Сеть", icon: "network" },
      { id: "routing", label: "Маршрутизация", icon: "route" },
      { id: "channels", label: "Интернет-каналы", icon: "globe" },
      { id: "vpn-servers", label: "VPN-доступ", icon: "shield-check" },
      { id: "wifi", label: "Wi-Fi", icon: "wifi" },
      { id: "traffic", label: "Скорость и QoS", icon: "gauge" },
      { id: "firewall", label: "Защита сети", icon: "brick-wall" },
      { id: "services", label: "Сетевые службы", icon: "server-cog" },
    ],
  },
  {
    group: "Роутер",
    items: [
      { id: "components", label: "Компоненты", icon: "package" },
      { id: "storage", label: "Диски и файлы", icon: "hard-drive" },
      { id: "system", label: "Система", icon: "settings" },
    ],
  },
  {
    group: "Служебное",
    items: [
      { id: "history", label: "История", icon: "history" },
      { id: "diagnostics", label: "Диагностика", icon: "activity" },
    ],
  },
];

function MenuIcon({ close }: { close: boolean }) {
  return <svg className="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">{close ? <><path d="m6 6 12 12"/><path d="M18 6 6 18"/></> : <><path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/></>}</svg>;
}

function ThemeIcon({ theme }: { theme: string }) {
  return <svg className="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{theme === "dark" ? <path d="M21 12.8A8.5 8.5 0 1 1 11.2 3 6.7 6.7 0 0 0 21 12.8Z"/> : theme === "light" ? <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.41M17.66 6.34l1.41-1.41"/></> : <><circle cx="12" cy="12" r="8"/><path d="M12 4v16a8 8 0 0 0 0-16Z"/></>}</svg>;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);
  const [sessionEnded, setSessionEnded] = useState(false);
  const onLogout = useCallback(() => setSession(null), []);
  const onLogin = useCallback((next: Session) => {
    setSessionEnded(false);
    setSession(next);
  }, []);

  useEffect(() => api.onUnauthorized(() => {
    setSessionEnded(true);
    setSession(null);
  }), []);

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
    return <Login onSuccess={onLogin} sessionEnded={sessionEnded} />;
  }

  return <PermissionContext.Provider value={session}><StatusPollingProvider key={session.username}><HintProvider session={session}><Shell session={session} onLogout={onLogout} /></HintProvider></StatusPollingProvider></PermissionContext.Provider>;
}

// ---------------------------------------------------------------------------
// Вход
// ---------------------------------------------------------------------------

function Login({ onSuccess, sessionEnded = false }: { onSuccess: (s: Session) => void; sessionEnded?: boolean }) {
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
          <h1 className="logo" aria-label="netOS">net<i>OS</i></h1>
        </div>

        <div className="login-body">
        {sessionEnded && <Notice title="Сессия завершена. Войдите снова" tone="warn">Несохранённые правки не применены.</Notice>}

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
        </div>
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
const STATUS_POLL_MS = 10_000;

// Порог, выше которого порт считается занятым трафиком за один опрос.
// Ниже — служебная болтовня вроде ARP и LLDP, мигать из-за неё незачем.
const PORT_BUSY_BYTES = 64 * 1024;

// PortStrip рисует физические порты роутера как гнёзда на лицевой панели:
// зелёный огонёк — есть линк, жёлтый мигает, пока через порт идёт трафик.
function PortStrip({ config, status }: { config: any; status: any }) {
  const previous = useRef<Map<string, number>>(new Map());
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const live = new Map<string, any>((status?.interfaces || []).map((i: any) => [i.name, i]));

  useEffect(() => {
    if (!status) return;
    const next = new Set<string>();
    for (const i of status.interfaces || []) {
      const total = (i.rx_bytes || 0) + (i.tx_bytes || 0);
      const before = previous.current.get(i.name);
      if (before !== undefined && total - before > PORT_BUSY_BYTES) next.add(i.name);
      previous.current.set(i.name, total);
    }
    setBusy(next);
  }, [status]);

  const ports = (config?.interfaces || []).filter((i: any) => i.type === "physical");
  if (ports.length === 0) return null;
  return (
    <div className="ports" aria-label="Порты роутера">
      {ports.map((port: any) => {
        const state = live.get(port.name);
        const up = !!state?.up;
        return (
          <div
            key={port.id}
            className={`port ${up ? "up" : ""} ${up && busy.has(port.name) ? "busy" : ""}`}
            title={`${port.name}: ${up ? "линк есть" : "нет линка"}`}
          >
            <div className="sock"><i className="l1" /><i className="l2" /></div>
            <span>{port.name}</span>
          </div>
        );
      })}
    </div>
  );
}

function Shell({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const readPage = useCallback((): PageID => {
    const id = window.location.hash.slice(1).split("?")[0];
    return NAV.flatMap((group) => group.items).some((item) => item.id === id)
      ? id as PageID : (NAV.flatMap(group => group.items).find(item => canAccess(session, item.id))?.id || "dashboard");
  }, [session]);
  const [page, setPage] = useState<PageID>(readPage);
  useEffect(() => {
    const navigate = () => { setPage(readPage()); setMobileNavOpen(false); };
    window.addEventListener("hashchange", navigate);
    return () => window.removeEventListener("hashchange", navigate);
  }, [readPage]);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [cfg, setCfg] = useState<any>(null);
  const [baseReservations, setBaseReservations] = useState<any[]>([]);
  const [configGeneration, setConfigGeneration] = useState(0);
  const [problems, setProblems] = useState<Problem[]>([]);
  const [dirty, setDirty] = useState(false);
  const [pending, setPending] = useState<{ until?: string } | null>(null);
  const [rollback, setRollback] = useState<any>(null);
  const [saveError, setSaveError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const discardInProgress = useRef(false);
  const [theme, setTheme] = useState<string>(
    () => localStorage.getItem("netos-theme") || "auto",
  );

  // Лицевая панель получает общий со страницами статус раз в десять секунд.
  const statusPolling = useStatusPolling();
  const [status, setStatus] = useState<any>(null);
  useEffect(() => {
    let cancelled = false;
    const unsubscribe = statusPolling.subscribe(STATUS_POLL_MS, false, request => {
      void request.then((next) => { if (!cancelled) setStatus(next); }).catch(() => {});
    });
    return () => { cancelled = true; unsubscribe(); };
  }, [statusPolling]);

  // Меню не прокручивается: всё, что в нём есть, должно быть видно сразу.
  // Если по высоте не помещается, уплотняем его ступенями.
  const sidebarRef = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    const sidebar = sidebarRef.current;
    if (!sidebar) return;
    const fit = () => {
      for (let level = 0; level <= 3; level++) {
        sidebar.dataset.fit = String(level);
        if (sidebar.scrollHeight <= sidebar.clientHeight) break;
      }
    };
    fit();
    window.addEventListener("resize", fit);
    return () => window.removeEventListener("resize", fit);
  }, [session]);

  // Прокручивается только область содержимого, поэтому при смене раздела
  // возвращаем наверх её, а не окно.
  const mainRef = useRef<HTMLElement>(null);
  useEffect(() => {
    mainRef.current?.scrollTo(0, 0);
  }, [page]);

  const saveTimer = useRef<number | undefined>(undefined);
  const pendingCfg = useRef<any>(null);
  // PUT-запросы выполняются строго по очереди: более старый ответ не должен
  // перезаписать на сервере конфигурацию, отправленную позже.
  const saveChain = useRef<Promise<void>>(Promise.resolve());
  const syncGeneration = useRef(0);

  useEffect(() => () => {
    syncGeneration.current++;
    pendingCfg.current = null;
    window.clearTimeout(saveTimer.current);
  }, []);

  const applyServerState = useCallback((res: ConfigResponse) => {
    setCfg(res.config);
    setBaseReservations(res.base_reservations || (!res.dirty ? res.config.dhcp?.reservations : []) || []);
    // Refresh local editors on authoritative reloads (rollback,
    // discard, history), never on debounced saves or individual keystrokes.
    setConfigGeneration((generation) => generation + 1);
    setSaveError("");
    setProblems(res.problems || []);
    setDirty(res.dirty);
    setRollback(res.rollback || null);
    setPending(res.pending_confirmation ? { until: res.confirm_deadline } : null);
  }, []);

  const reload = useCallback(async () => {
    const generation = ++syncGeneration.current;
    setLoading(true);
    setLoadError("");
    pendingCfg.current = null;
    window.clearTimeout(saveTimer.current);
    try {
      const res = await api.getConfig();
      if (generation !== syncGeneration.current) return;
      applyServerState(res);
    } catch (err) {
      if (generation !== syncGeneration.current) return;
      if (err instanceof ApiError && err.status === 401) onLogout();
      else setLoadError(err instanceof ApiError ? err.message : "Нет связи с роутером");
    } finally {
      if (generation === syncGeneration.current) setLoading(false);
    }
  }, [applyServerState, onLogout]);

  const discard = useCallback(async () => {
    // Invalidate queued saves before waiting for the in-flight PUT. Otherwise
    // its late response (or a debounce timer) can recreate the discarded draft.
    if (discardInProgress.current) return;
    discardInProgress.current = true;
    setDiscarding(true);
    const generation = ++syncGeneration.current;
    pendingCfg.current = null;
    window.clearTimeout(saveTimer.current);
    try {
      await saveChain.current;
      try {
        await api.discardDraft();
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 409) throw err;
        // Rollback/restart may have already removed this draft. Never retry
        // DELETE semantics blindly: another tab may have saved new edits.
        const current = await api.getConfig();
        if (generation !== syncGeneration.current) throw err;
        applyServerState(current);
        if (current.pending_confirmation) {
          throw new ApiError(409, "Применение ожидает подтверждения; проверьте связь или откатите изменения.");
        }
        if (current.dirty) {
          throw new ApiError(409, "Черновик изменился. Показаны актуальные настройки; проверьте их перед повторной отменой.");
        }
        setLoadError("");
        return;
      }
      const res = await api.getConfig();
      if (generation !== syncGeneration.current) throw new Error("Конфигурация обновилась во время отмены");
      applyServerState(res);
      setLoadError("");
    } finally {
      discardInProgress.current = false;
      setDiscarding(false);
    }
  }, [applyServerState]);

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

    const generation = syncGeneration.current;
    const job = saveChain.current.then(async () => {
      if (generation !== syncGeneration.current) return;
      try {
        const res = await api.saveConfig(next);
        if (generation !== syncGeneration.current) return;
        setProblems(res.problems || []);
        // Черновик, совпавший с применённой конфигурацией, черновиком быть
        // перестаёт: сервер отвечает dirty=false, и полоса применения уходит
        // сама. Иначе правка, возвращённая к исходному значению, до конца
        // сеанса предлагала бы применить пустоту.
        setDirty(res.dirty);
        setSaveError("");
      } catch (err) {
        if (generation !== syncGeneration.current) return;
        if (err instanceof ApiError) {
          setProblems(err.problems || []);
          setSaveError(err.problems?.length ? "" : err.message);
        } else {
          // Отказ неизвестной природы всё равно означает несохранённую правку,
          // и молчать о ней нельзя.
          setSaveError("Не удалось сохранить изменение");
        }
        setDirty(true);
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
      if (!canAccess(session, page, true) || discardInProgress.current) return;
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
    [flush, session, page],
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

  const themeName = theme === "dark" ? "тёмная" : theme === "light" ? "светлая" : "системная";

  return (
    <div className="app">
      <header className="panel">
        <div className="brand">
          <span className="logo">netOS</span>
          <span className="host">{cfg?.system?.hostname || "…"}</span>
        </div>
        <PortStrip config={cfg} status={status} />
        <div className="meta">
          {status && <span>РАБОТАЕТ <b>{formatUptime(status.uptime_seconds)}</b></span>}
          <button
            type="button"
            className="icon-btn"
            title={`Тема: ${themeName}`}
            aria-label={`Тема оформления: ${themeName}. Сменить`}
            onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "auto" : "dark")}
          >
            <ThemeIcon theme={theme} />
          </button>
          <HintToggle />
          <button
            type="button"
            className="icon-btn mobile-nav-toggle"
            aria-label={mobileNavOpen ? "Закрыть меню" : "Открыть меню"}
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <MenuIcon close={mobileNavOpen} />
          </button>
        </div>
      </header>

      <div className="shell">
      <aside ref={sidebarRef} className={`sidebar ${mobileNavOpen ? "mobile-open" : ""}`}>
        <nav className="nav">
          {NAV.map((group) => ({
            ...group,
            // Rendered service configurations can contain private keys and
            // credentials. The API correctly keeps them admin-only, so do not
            // offer a viewer a page that can only end in 403.
            items: group.items.filter((item) => canAccess(session, item.id)),
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
                    window.location.hash = item.id;
                    setPage(item.id);
                    setMobileNavOpen(false);
                  }}
                >
                  <span className="icon"><Icon name={item.icon} /></span>
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
      </aside>

      <main className="main" ref={mainRef}>
        <div className="page">
          <HintSaveError />
          {canAccess(session, page) && !canAccess(session, page, true) && (
            <Notice tone="info" title="Режим просмотра">
              В этом разделе доступен только просмотр.
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

          {loadError && <Notice tone="danger" title="Не удалось загрузить конфигурацию">
            <div role="alert">{loadError}</div>
            <button className="btn" disabled={loading} onClick={() => void reload()}>Повторить</button>
          </Notice>}

          {!canAccess(session, page) ? <Notice tone="warn" title="Нет доступа к разделу" /> : !cfg ? (loadError ? null :
            <Spinner />
          ) : (
            <fieldset disabled={discarding || (!canAccess(session, page, true) && !["dashboard", "map", "history", "diagnostics"].includes(page))} style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}>
              {page === "dashboard" && <Dashboard config={cfg} patch={patch} />}
              {page === "map" && <MapPage config={cfg} />}
              {page === "clients" && <Clients key={configGeneration} config={cfg} patch={patch} baseReservations={baseReservations} />}
              {page === "network" && (
                <NetworkPage config={cfg} patch={patch} problems={problems} />
              )}
              {page === "routing" && <RoutingPage config={cfg} patch={patch} />}
              {page === "channels" && <ChannelsPage key={configGeneration} config={cfg} patch={patch} />}
              {page === "vpn-servers" && <VPNServersPage key={configGeneration} config={cfg} patch={patch} beforeRead={flushNow} />}
              {page === "wifi" && <WiFiPage config={cfg} patch={patch} />}
              {page === "storage" && <StoragePage config={cfg} patch={patch} admin={canAccess(session, "storage", true)} />}
              {page === "traffic" && <TrafficPage config={cfg} patch={patch} />}
              {page === "services" && <ServicesPage config={cfg} patch={patch} problems={problems} />}
              {page === "firewall" && <FirewallPage config={cfg} patch={patch} problems={problems} />}
              {page === "components" && <ComponentsPage config={cfg} patch={patch} />}
              {page === "system" && (
                <SystemPage config={cfg} patch={patch} session={session} onSessionEnded={onLogout} onConfigReplaced={reload} />
              )}
              {page === "history" && <HistoryPage onRestored={reload} />}
              {page === "diagnostics" && <DiagnosticsPage admin={session.role === "admin"} dnsLogging={!!cfg.dns?.query_log} />}
            </fieldset>
          )}
        </div>
      </main>
      </div>

      {(session.role === "admin" || Object.values(session.permissions || {}).includes("manage")) && (
        <ApplyBar
          config={cfg}
          dirty={dirty}
          pending={pending}
          errorCount={errors.length}
          problems={problems}
          onFlush={flushNow}
          onDiscard={discard}
          onReload={reload}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Панель применения
// ---------------------------------------------------------------------------

// ProblemList печатает сами замечания валидатора. Ошибки идут первыми и
// полностью: не увидев причины, администратор не поймёт, какую из строк
// править. Предупреждения тоже показываем — они объясняют, почему настройка
// принята, но работать не будет.
function ProblemList({ problems }: { problems: Problem[] }) {
  const groups = [
    { kind: "error", title: "Нужно исправить", items: problems.filter((p) => p.severity === "error") },
    { kind: "warning", title: "Обратите внимание", items: problems.filter((p) => p.severity !== "error") },
  ];
  return (
    <div className="apply-problems">
      {groups.filter((group) => group.items.length > 0).map((group) => (
        <section className={`apply-problem-group ${group.kind}`} key={group.kind} aria-label={group.title}>
          <div className="apply-problem-heading">
            <span className="apply-problem-icon" aria-hidden="true">{group.kind === "error" ? "!" : "i"}</span>
            <strong>{group.title}</strong>
            <span className="apply-problem-count">{group.items.length}</span>
          </div>
          <ul>{group.items.map((p, i) => <li key={i}>{p.message}</li>)}</ul>
        </section>
      ))}
    </div>
  );
}

function ApplyBar({
  config,
  dirty,
  pending,
  errorCount,
  problems,
  onFlush,
  onDiscard,
  onReload,
}: {
  config: any;
  dirty: boolean;
  pending: { until?: string } | null;
  errorCount: number;
  problems: Problem[];
  onFlush: () => Promise<void>;
  onDiscard: () => Promise<void>;
  onReload: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [plan, setPlan] = useState<PlanResponse | null>(null);
  const latestConfig = useRef(config);
  latestConfig.current = config;
  useEffect(() => { setPlan(null); }, [config]);
  const [remaining, setRemaining] = useState(0);
  const timerRef = useRef<number | undefined>(undefined);
  const barRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const bar = barRef.current;
    if (!bar) return;
    const update = () => document.documentElement.style.setProperty("--applybar-height", `${bar.getBoundingClientRect().height}px`);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(bar);
    return () => {
      observer.disconnect();
      document.documentElement.style.removeProperty("--applybar-height");
    };
  }, [dirty, pending, !!error]);

  useEffect(() => {
    if (!dirty) setPlan(null);
  }, [dirty]);

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
      <div className="applybar" ref={barRef}>
        <div className="msg">
          <strong>Подтвердите изменения</strong>
          <div className="dim">
            Если связь с роутером потеряна, ничего не нажимайте — конфигурация вернётся
            автоматически через <span className="countdown">{remaining}</span> с.
          </div>
          {error && <ActionError message={error} />}
        </div>
        <div className="actions">
          <button
            className="btn"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                await api.rollback();
                await onReload();
              } catch (err) {
                setError(err instanceof ApiError ? err.message : "Не удалось откатить изменения");
                await onReload();
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
              setError("");
              try {
                await api.confirm();
                await onReload();
              } catch (err) {
                setError(err instanceof ApiError ? err.message : "Не удалось подтвердить изменения");
                await onReload();
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

  // A failed Apply may roll the server back and clear the draft before the
  // request returns its error. Keep the bar visible for that error even though
  // the authoritative configuration is no longer dirty; otherwise the admin
  // sees the buttons disappear and then reappear with no explanation.
  if (!dirty && !error) return null;

  return (
    <div className="applybar" ref={barRef}>
      <div className="msg">
        <strong>{dirty ? "Есть несохранённые изменения" : "Изменения не применены"}</strong>
        <div className="dim">
          {errorCount > 0 ? (
            <ProblemList problems={problems} />
          ) : error || plan ? (
            null
          ) : (
            "Изменения вступят в силу сразу, перезагрузка не нужна."
          )}
        </div>
        {error && <ActionError message={error} />}
        {plan !== null && <PlanPreview plan={plan} />}
      </div>
      <div className="actions">
        <button
          className="btn ghost"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await onDiscard();
              setError("");
              setPlan(null);
            } catch (err) {
              setError(err instanceof ApiError ? err.message : "Не удалось отменить черновик");
            } finally {
              setBusy(false);
            }
          }}
        >
          Отменить
        </button>
        <button
          className="btn"
          disabled={busy || errorCount > 0}
          onClick={async () => {
            setBusy(true);
            setError("");
            setPlan(null);
            const requestedConfig = latestConfig.current;
            try {
              await onFlush();
              const response = await api.plan();
              if (requestedConfig === latestConfig.current) setPlan(response);
            } catch (err) {
              setPlan(null);
              setError(err instanceof ApiError ? err.message : "Не удалось построить план");
            } finally {
              setBusy(false);
            }
          }}
        >
          Показать план
        </button>
        <button
          className="btn primary"
          disabled={busy || errorCount > 0}
          onClick={async () => {
            setBusy(true);
            setError("");
            setPlan(null);
            try {
              await onFlush();
              try {
                await api.apply("изменения из панели");
              } finally {
                // Network changes can lose the response after a successful
                // apply or rollback. Refresh the authoritative draft/version
                // even on failure, but never discard edits when flush failed.
                await onReload();
              }
            } catch (err) {
              setError(err instanceof ApiError ? err.message : "Применение не удалось");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Подождите…" : "Применить"}
        </button>
      </div>
    </div>
  );
}
