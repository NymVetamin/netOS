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

export function automaticTables(names: string[], tables: {name: string; number: number}[] = [],
  channels: {index: number; name: string; type: string}[] = []) {
  if (!names.length) return [];
  const excluded = new Set(["main", "local", "default"]);
  for (const table of tables) {
    excluded.add(table.name);
    excluded.add(String(table.number));
  }
  const visible = names.filter(name => !excluded.has(name));
  if (!visible.length) return [];
  const byName = new Map<string, (typeof channels)[number]>();
  for (const channel of channels) {
    if (channel.type === "direct") continue;
    for (const key of [`netos-ch${channel.index}`, String(1000 + channel.index)]) {
      if (!byName.has(key)) byName.set(key, channel);
    }
  }
  return visible.map(name => {
    const channel = byName.get(name);
    if (channel) return { name, number: String(1000 + channel.index), owner: `Интернет-канал: ${channel.name} (${channel.type})` };
    return { name, number: /^\d+$/.test(name) ? name : "—", owner: "Таблица ОС" };
  });
}
