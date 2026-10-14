export function channelReferences(config: any, id: string): { owner: any; key: string; label: string }[] {
  const refs: { owner: any; key: string; label: string }[] = [];
  const add = (owner: any, key: string, label: string) => { if (owner[key] === id) refs.push({ owner, key, label }); };
  for (const c of config.clients || []) add(c, "channel", `Клиент: ${c.name || c.mac || c.id}`);
  for (const n of config.networks || []) add(n, "default_channel", `Сегмент: ${n.name || n.id}`);
  for (const p of config.policies || []) add(p, "channel", `Правило маршрутизации: ${p.name || p.id}`);
  for (const c of config.channels || []) if (c.id !== id) add(c, "fallback", `Запасной выход канала: ${c.name || c.id}`);
  for (const u of config.dns?.upstreams || []) add(u, "channel", `DNS: ${u.name || u.address || u.id}`);
  for (const r of config.dns?.split_rules || []) add(r, "channel", `Правило DNS: ${r.name || r.id}`);
  for (const s of config.vpn_servers || []) {
    add(s, "default_channel", `VPN-сервер: ${s.name || s.id}`);
    for (const p of s.peers || []) add(p, "channel", `VPN-клиент: ${s.name || s.id} / ${p.name || p.id}`);
  }
  return refs;
}

// Replacing incoming fallback edges must not turn a fallback chain into a cycle.
export function canReplaceChannel(config: any, removed: string, replacement: string): boolean {
  const channels = config.channels || [];
  if (removed === replacement || !channels.some((c: any) => c.id === replacement && c.enabled)) return false;
  const visited = new Set<string>();
  let id = replacement;
  while (id) {
    if (id === removed || visited.has(id)) return false;
    visited.add(id);
    id = channels.find((c: any) => c.id === id)?.fallback || "";
  }
  return true;
}
