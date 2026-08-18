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
};

export type Session = {
  username: string;
  role: string;
  must_change: boolean;
  last_login?: string;
};

let csrfToken: string | null = null;

export class ApiError extends Error {
  status: number;
  problems?: Problem[];

  constructor(status: number, message: string, problems?: Problem[]) {
    super(message);
    this.status = status;
    this.problems = problems;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
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

  session: () => request<Session>("GET", "/api/session"),

  changePassword: (current: string, next: string) =>
    request<{ ok: boolean }>("POST", "/api/password", { current, new: next }),

  getConfig: () => request<ConfigResponse>("GET", "/api/config"),
  saveConfig: (config: any) => request<ConfigResponse>("PUT", "/api/config", config),
  discardDraft: () => request<{ ok: boolean }>("POST", "/api/config/discard"),
  plan: () => request<{ actions: PlanAction[] | null }>("POST", "/api/config/plan"),
  apply: (comment: string) =>
    request<{ needs_confirm: boolean; deadline?: string; revision: number }>(
      "POST",
      "/api/config/apply",
      { comment },
    ),
  confirm: () => request<{ ok: boolean }>("POST", "/api/config/confirm"),
  rollback: () => request<{ ok: boolean }>("POST", "/api/config/rollback"),

  catalog: () => request<{ components: ComponentInfo[] }>("GET", "/api/catalog"),
  status: () => request<any>("GET", "/api/status"),
  clients: () => request<{ clients: any[] }>("GET", "/api/clients"),
  interfaces: () => request<{ interfaces: any[] }>("GET", "/api/interfaces"),
  leases: () => request<{ leases: any[] }>("GET", "/api/leases"),
  arp: () => request<{ arp: any[] }>("GET", "/api/arp"),
  routes: () => request<{ routes: string; rules: string }>("GET", "/api/routes"),
  audit: (limit = 100) => request<{ entries: any[] }>("GET", `/api/audit?limit=${limit}`),
  revisions: (limit = 50) => request<{ revisions: any[] }>("GET", `/api/revisions?limit=${limit}`),
  restoreRevision: (id: number) =>
    request<ConfigResponse>("POST", `/api/revisions/${id}/restore`),

  async render(kind: "iptables" | "dnsmasq"): Promise<string> {
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
