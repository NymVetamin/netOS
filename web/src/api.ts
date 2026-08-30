// Обращения к API панели.
//
// CSRF-токен выдаётся при входе и живёт в памяти вкладки: класть его в
// localStorage незачем, а перезагрузка страницы всё равно требует проверки
// сессии, при которой токен обновляется.

export type Problem = {
  path: string;
  message: string;
  severity: "error" | "warning";
};

export type RollbackInfo = {
  at: string;
  revision: number;
  reason: "timeout" | "health" | "manual";
  details?: string;
};

export type ConfigResponse = {
  config: any;
  dirty: boolean;
  problems: Problem[];
  pending_confirmation: boolean;
  confirm_deadline?: string;
  rollback?: RollbackInfo;
  draft_version: number;
};

export type PlanAction = {
  subsystem: string;
  kind: string;
  target: string;
  detail?: string;
  disruptive: boolean;
};

export type ComponentInfo = {
  id: string;
  title: string;
  group: string;
  description: string;
  packages?: string[];
  provides?: string[];
  size_hint?: string;
  external?: boolean;
  run_units?: string[];
};

// CatalogResponse — каталог вместе с живым состоянием машины. installed
// говорит, что пакет лежит на диске, running — что демон компонента работает
// прямо сейчас. Желаемое состояние панель знает из конфигурации, и эти два
// поля нужны, чтобы расхождение было видно.
export type CatalogResponse = {
  components: ComponentInfo[];
  installed?: Record<string, boolean>;
  running?: Record<string, boolean>;
};

// RouteEntry — разобранная запись таблицы маршрутизации.
export type RouteEntry = {
  destination: string;
  gateway: string;
  interface: string;
  source: string;
  metric: number;
  // origin: netos | netos-static | kernel | dhcp | static | boot | ra
  origin: string;
  table: string;
  raw: string;
};

export type Session = {
  username: string;
  role: string;
  last_login?: string;
  csrf_token: string;
};

let csrfToken: string | null = null;
let draftVersion: number | null = null;

export class ApiError extends Error {
  status: number;
  problems?: Problem[];

  constructor(status: number, message: string, problems?: Problem[]) {
    super(message);
    this.status = status;
    this.problems = problems;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
): Promise<T> {
  const headers: Record<string, string> = { ...(extraHeaders || {}) };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (csrfToken && method !== "GET") headers["X-NetOS-CSRF"] = csrfToken;

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  const isJSON = res.headers.get("content-type")?.includes("application/json");
  const data = isJSON && text ? JSON.parse(text) : text;

  if (!res.ok) {
    const message = isJSON && data?.error ? data.error : `Ошибка ${res.status}`;
    throw new ApiError(res.status, message, isJSON ? data?.problems : undefined);
  }
  return data as T;
}

export const api = {
  hasToken: () => csrfToken !== null,

  async login(username: string, password: string) {
    const res = await request<{ csrf_token: string } & Session>("POST", "/api/login", {
      username,
      password,
    });
    csrfToken = res.csrf_token;
    return res;
  },

  async logout() {
    try {
      await request("POST", "/api/logout");
    } finally {
      csrfToken = null;
    }
  },

  async session() {
    const res = await request<Session>("GET", "/api/session");
    csrfToken = res.csrf_token;
    return res;
  },

  changePassword: (current: string, next: string) =>
    request<{ ok: boolean }>("POST", "/api/password", { current, new: next }),

  wireGuardKeypair: (privateKey?: string) =>
    request<{ private_key: string; public_key: string }>(
      "POST", "/api/wireguard/keypair", privateKey ? { private_key: privateKey } : undefined,
    ),

  xrayKeypair: (privateKey?: string) =>
    request<{ private_key: string; public_key: string }>(
      "POST", "/api/xray/keypair", privateKey ? { private_key: privateKey } : undefined,
    ),

  async getConfig() {
    const res = await request<ConfigResponse>("GET", "/api/config");
    draftVersion = res.draft_version;
    return res;
  },
  async saveConfig(config: any) {
    if (draftVersion === null) throw new ApiError(409, "Сначала обновите конфигурацию");
    const res = await request<ConfigResponse>("PUT", "/api/config", config, {
      "If-Match": String(draftVersion),
    });
    draftVersion = res.draft_version;
    return res;
  },
  async discardDraft() {
    if (draftVersion === null) throw new ApiError(409, "Сначала обновите конфигурацию");
    const res = await request<{ ok: boolean; draft_version: number }>(
      "POST", "/api/config/discard", undefined, { "If-Match": String(draftVersion) },
    );
    draftVersion = res.draft_version;
    return res;
  },
  plan: () => request<{ actions: PlanAction[] | null }>("POST", "/api/config/plan"),
  apply: (comment: string) => {
    if (draftVersion === null) return Promise.reject(new ApiError(409, "Сначала обновите конфигурацию"));
    return request<{ needs_confirm: boolean; deadline?: string; revision: number }>(
      "POST",
      "/api/config/apply",
      { comment, draft_version: draftVersion },
    );
  },
  confirm: () => request<{ ok: boolean }>("POST", "/api/config/confirm"),
  rollback: () => request<{ ok: boolean }>("POST", "/api/config/rollback"),

  catalog: () => request<CatalogResponse>("GET", "/api/catalog"),
  status: () => request<any>("GET", "/api/status"),
  clients: () => request<{ clients: any[] }>("GET", "/api/clients"),
  interfaces: () => request<{ interfaces: any[] }>("GET", "/api/interfaces"),
  leases: () => request<{ leases: any[] }>("GET", "/api/leases"),
  arp: () => request<{ arp: any[] }>("GET", "/api/arp"),
  routes: () =>
    request<{ routes: string; rules: string; parsed: RouteEntry[] }>("GET", "/api/routes"),
  audit: (limit = 100) => request<{ entries: any[] }>("GET", `/api/audit?limit=${limit}`),
  revisions: (limit = 50) => request<{ revisions: any[] }>("GET", `/api/revisions?limit=${limit}`),
  async restoreRevision(id: number) {
    if (draftVersion === null) throw new ApiError(409, "Сначала обновите конфигурацию");
    const res = await request<ConfigResponse>("POST", `/api/revisions/${id}/restore`, undefined, {
      "If-Match": String(draftVersion),
    });
    draftVersion = res.draft_version;
    return res;
  },

  // Список артефактов приходит с сервера: какие конфиги лежат на машине,
  // зависит от выбранных демонов, и зашитый в панели перечень показывал бы
  // dnsmasq даже там, где работают unbound и ISC DHCP.
  async renderList(): Promise<{ id: string; title: string }[]> {
    const res = await request<{ artifacts: { id: string; title: string }[] }>("GET", "/api/render");
    return res.artifacts || [];
  },

  async render(kind: string): Promise<string> {
    const res = await fetch(`/api/render/${kind}`, { credentials: "same-origin" });
    if (!res.ok) throw new ApiError(res.status, `Ошибка ${res.status}`);
    return res.text();
  },
};

// --- форматирование ---

export function formatBytes(n: number): string {
  if (!n) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  const value = n / Math.pow(1024, i);
  return `${value >= 100 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

export function formatUptime(seconds: number): string {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d} д ${h} ч`;
  if (h > 0) return `${h} ч ${m} мин`;
  return `${m} мин`;
}

export function formatTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
