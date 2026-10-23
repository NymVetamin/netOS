function ipv4(value: string): number | undefined {
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) return;
  const parts = value.split('.').map(Number);
  if (parts.some(n => n > 255)) return;
  return parts.reduce((n, part) => n * 256 + part, 0);
}

function subnet(network: any) {
  const [address, bits] = String(network?.router_address || '').split('/');
  const router = ipv4(address), prefix = Number(bits);
  if (router === undefined || !/^\d+$/.test(bits || '') || prefix < 0 || prefix > 32) return;
  const size = 2 ** (32 - prefix), first = Math.floor(router / size) * size;
  return { router, first, last: first + size - 1, prefix };
}

export function reservationNetwork(config: any, client: any): string {
  const networks = config.networks || [];
  const byInterface = client.interface ? networks.filter((n: any) =>
    (config.interfaces || []).some((i: any) => i.id === n.interface && i.name === client.interface)) : [];
  if (byInterface.length === 1) return byInterface[0].id;
  if (byInterface.length > 1) return '';
  const address = ipv4(client.ip || '');
  const matches = networks.filter((n: any) => {
    const range = subnet(n);
    return range && address !== undefined && address >= range.first && address <= range.last;
  });
  return matches.length === 1 ? matches[0].id : '';
}

export function reservationError(config: any, mac: string, ip: string, networkID: string, devices: any[] = []): string {
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) return 'Введите MAC-адрес в формате aa:bb:cc:dd:ee:ff';
  const network = (config.networks || []).find((n: any) => n.id === networkID);
  if (!network) return 'Выберите сегмент для закрепления адреса';
  const address = ipv4(ip);
  if (address === undefined) return 'Введите корректный IPv4-адрес, например 192.168.10.50';
  const range = subnet(network);
  if (!range || address < range.first || address > range.last) return 'Адрес не принадлежит подсети выбранного сегмента';
  if (address === range.router || ip === network.dhcp_pool?.gateway) return 'Нельзя закрепить адрес роутера или DHCP-шлюза';
  if (range.prefix <= 30 && (address === range.first || address === range.last)) return 'Нельзя закрепить адрес сети или широковещательный адрес';
  const other = (c: any) => String(c.mac).toLowerCase() !== mac.toLowerCase() && c.ip === ip;
  if ((config.dhcp?.reservations || []).some(other)) return 'Адрес уже закреплён за другим устройством';
  if (devices.some(other)) return 'Адрес уже используется другим устройством';
  return '';
}

export function reservationHostname(value: string): string {
  return value.length <= 253 && value.split('.').every(label =>
    label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)) ? value : '';
}
