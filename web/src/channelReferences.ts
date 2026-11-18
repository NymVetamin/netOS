function visitChannelReferences(config: any, add: (owner: any, key: string, label: string) => void) {
  for (const c of config.clients || []) add(c, "channel", `Клиент: ${c.name || c.mac || c.id}`);
  for (const n of config.networks || []) add(n, "default_channel", `Сегмент: ${n.name || n.id}`);
  for (const p of config.policies || []) add(p, "channel", `Правило маршрутизации: ${p.name || p.id}`);
  for (const c of config.channels || []) add(c, "fallback", `Запасной выход канала: ${c.name || c.id}`);
  for (const u of config.dns?.upstreams || []) add(u, "channel", `DNS: ${u.name || u.address || u.id}`);
  for (const r of config.dns?.split_rules || []) add(r, "channel", `Правило DNS: ${r.name || r.id}`);
  for (const s of config.vpn_servers || []) {
    add(s, "default_channel", `VPN-сервер: ${s.name || s.id}`);
    for (const p of s.peers || []) add(p, "channel", `VPN-клиент: ${s.name || s.id} / ${p.name || p.id}`);
  }
  if (config.socks?.enabled) add(config.socks, "channel", "SOCKS5-прокси");
}

export function channelReferences(config: any, id?: string): { owner: any; key: string; label: string }[] {
  const refs: { owner: any; key: string; label: string }[] = [];
  visitChannelReferences(config, (owner, key, label) => {
    const target = owner[key];
    if (target && (id === undefined || target === id) && !(key === "fallback" && owner.id === id)) {
      refs.push({ owner, key, label });
    }
  });
  return refs;
}

export function channelReferenceLookup(config: any): (id?: string) => boolean {
  let hasAny = false;
  const ids = new Set<string>();
  visitChannelReferences(config, (owner, key) => {
    const target = owner[key];
    if (!target) return;
    if (key !== "fallback" || owner.id !== undefined) hasAny = true;
    if (key !== "fallback" || owner.id !== target) ids.add(target);
  });
  // Older drafts can contain a row without an ID. Its guard used the unfiltered list.
  return id => id === undefined ? hasAny : ids.has(id);
}

// Replacing incoming fallback edges must not turn a fallback chain into a cycle.
export function replacementChannelIDs(channels: any[], removed: string): Set<string> {
  const fallback = new Map<string, string>();
  const candidates = new Set<string>();
  for (const channel of channels) {
    if (!fallback.has(channel.id)) fallback.set(channel.id, channel.fallback || "");
    if (channel.enabled && channel.id !== removed) candidates.add(channel.id);
  }
  const safe = new Map<string, boolean>([[removed, false]]);
  const path: string[] = [];
  for (const start of candidates) {
    let id = start;
    while (id && !safe.has(id)) {
      safe.set(id, false); // Revisiting an unfinished path means a cycle.
      path.push(id);
      id = fallback.get(id) || "";
    }
    const allowed = !id || safe.get(id) === true;
    for (const step of path) safe.set(step, allowed);
    path.length = 0;
    if (!allowed) candidates.delete(start);
  }
  return candidates;
}
