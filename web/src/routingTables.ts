import type { RouteEntry } from "./api";

export function nextRouteTable(tables: {name: string; number: number}[]) {
  const names = new Set<string>();
  const numbers = new Set<number>();
  for (const table of tables) {
    names.add(table.name);
    numbers.add(table.number);
  }
  let suffix = tables.length + 1;
  while (names.has(`netos-t${suffix}`)) suffix++;
  for (let offset = 0; offset < 252; offset++) {
    const number = 1 + (100 + offset) % 252;
    if (!numbers.has(number)) return {name: `netos-t${suffix}`, number};
  }
  return null;
}

export function nextRulePriority(rules: {priority: number}[]): number {
  const used = new Set<number>();
  for (const rule of rules) used.add(rule.priority);
  for (let priority = 20100; priority <= 29999; priority += 10) {
    if (!used.has(priority)) return priority;
  }
  for (let priority = 20000; priority <= 29999; priority++) {
    if (!used.has(priority)) return priority;
  }
  // Duplicate priorities are valid and produce a validation warning.
  return 20100;
}

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
