// Reservations remain manageable even after a device disappears from DHCP/ARP.
export function localDevices(clients: any[], config: any): any[] {
  const rows = new Map(clients.map(c => [String(c.mac).toLowerCase(), { ...c, mac: String(c.mac).toLowerCase() }]));
  for (const r of config.dhcp?.reservations || []) {
    const mac = String(r.mac).toLowerCase();
    if (!rows.has(mac)) rows.set(mac, { mac, ip: r.ip, hostname: r.hostname, online: false, source: "reservation",
      interface: (config.interfaces || []).find((i: any) => i.id === (config.networks || []).find((n: any) => n.id === r.network)?.interface)?.name });
  }
  return [...rows.values()];
}
