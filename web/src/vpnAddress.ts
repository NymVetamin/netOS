import { parseCIDR } from "./access";

function formatIPv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

export function nextVPNPeerAddress(server: { subnet?: string; type: string; peers?: { address?: string }[] }): string {
  const cidr = server.subnet || "";
  const subnet = parseCIDR(cidr);
  if (!subnet || subnet.bits > 30) throw new Error("Укажите корректную IPv4-подсеть VPN-сервера");

  const used = new Set((server.peers || []).map(peer => peer.address));
  used.add(cidr.split("/")[0]);
  const first = subnet.net + 1;
  if (server.type === "ocserv") used.add(formatIPv4(first));
  const broadcast = subnet.net + 2 ** (32 - subnet.bits) - 1;
  for (let candidate = first; candidate < broadcast; candidate++) {
    const address = formatIPv4(candidate);
    if (!used.has(address)) return address;
  }
  throw new Error("В адресном пуле VPN не осталось свободных адресов");
}
