// Reservations remain manageable even after a device disappears from DHCP/ARP.
export function localDevices(clients: any[], config: any): any[] {
  const rows = new Map(clients.map(c => [String(c.mac).toLowerCase(), { ...c, mac: String(c.mac).toLowerCase() }]));
  let networks: Map<string, any> | undefined;
  let interfaces: Map<string, any> | undefined;
  for (const r of config.dhcp?.reservations || []) {
    const mac = String(r.mac).toLowerCase();
    if (rows.has(mac)) continue;
    if (!networks) {
      networks = new Map();
      interfaces = new Map();
      // Preserve the first match, including in an incomplete draft.
      for (const n of config.networks || []) if (!networks.has(n.id)) networks.set(n.id, n);
      for (const i of config.interfaces || []) if (!interfaces.has(i.id)) interfaces.set(i.id, i);
    }
    rows.set(mac, { mac, ip: r.ip, hostname: r.hostname, online: false, source: "reservation",
      interface: interfaces!.get(networks.get(r.network)?.interface)?.name });
  }
  return [...rows.values()];
}
