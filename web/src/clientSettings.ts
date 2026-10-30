export function updateClientSettings(config: any, mac: string, changes: Record<string, unknown>, network: string, baseMACs: ReadonlySet<string>) {
  const defaults: Record<string, unknown> = { name: "", blocked: false, down_kbit: 0, up_kbit: 0, channel: "", comment: "" };
  const clients = config.clients ||= [];
  const index = clients.findIndex((c: any) => String(c.mac).toLowerCase() === mac.toLowerCase());
  const client = index >= 0 ? clients[index] : { id: "cl-" + mac.replace(/:/g, ""), mac, name: "", blocked: false, down_kbit: 0, up_kbit: 0, network };
  Object.assign(client, changes);
  // Identity and auto-detected segment are metadata, not a user override.
  // Unknown fields deliberately prevent deletion when new settings are added.
  const empty = Object.entries(client).every(([key, value]) =>
    ["id", "mac", "network"].includes(key) || (Object.hasOwn(defaults, key) && value === defaults[key]));
  if (!baseMACs.has(mac.toLowerCase()) && empty) {
    if (index >= 0) clients.splice(index, 1);
  } else if (index < 0) clients.push(client);
}
