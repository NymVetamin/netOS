// Preserve Array.find's first match, including an absent public key. Callers
// choose explicitly whether their protocol requires matching the key.
export function indexClientStatuses<T extends { id: string; public_key?: unknown }>(rows: readonly T[]) {
  const first = new Map<string, T>();
  const keyed = new Map<string, Map<unknown, T>>();
  for (const row of rows) {
    if (!first.has(row.id)) first.set(row.id, row);
    let keys = keyed.get(row.id);
    if (!keys) { keys = new Map(); keyed.set(row.id, keys); }
    if (!keys.has(row.public_key)) keys.set(row.public_key, row);
  }
  return {
    get: (id: string) => first.get(id),
    getWithKey: (id: string, key: unknown) => keyed.get(id)?.get(key),
  };
}
