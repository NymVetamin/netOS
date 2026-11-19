import type { RouteEntry } from "./api";

export function observedTables(routes: RouteEntry[], rules: string): string[] {
  const tables = new Set(routes.map(r => canonicalTable(r.table || "main")));
  for (const match of rules.matchAll(/\b(?:lookup|table)\s+(\S+)/g)) tables.add(canonicalTable(match[1]));
  return [...tables].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

export function canonicalTable(name: string): string {
  switch (name) {
    case "253": return "default";
    case "254": return "main";
    case "255": return "local";
    default: return name;
  }
}

export function tableDetails(name: string, config: any) {
  const manual = (config.routing?.tables || []).find((t: any) => t.name === name || String(t.number) === name);
  if (manual) return { number: String(manual.number), owner: manual.comment || "Пользовательская таблица", manual: true };
  const channel = (config.channels || []).find((c: any) => c.type !== "direct" &&
    (name === `netos-ch${c.index}` || name === String(1000 + c.index)));
  if (channel) return { number: String(1000 + channel.index), owner: `Интернет-канал: ${channel.name} (${channel.type})`, manual: false };
  return { number: /^\d+$/.test(name) ? name : "—", owner: "Таблица ОС", manual: false };
}
