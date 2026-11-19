import { parseCIDR } from "./access";

export function segmentAddresses(networks: {router_address?: string}[], servers: {enabled?: boolean; subnet?: string}[]) {
  const used = new Uint8Array(256);
  const base = 192 * 65536 + 168 * 256; // 192.168.0.0 in units of /24.
  function reserve(cidr?: string) {
    const range = parseCIDR(cidr || "");
    if (!range) return;
    const first = Math.floor(range.net / 256) - base;
    const last = Math.floor((range.net + 2 ** (32 - range.bits) - 1) / 256) - base;
    if (first < 256 && last >= 0) used.fill(1, Math.max(0, first), Math.min(256, last + 1));
  }
  for (const network of networks) reserve(network.router_address);
  for (const server of servers) if (server.enabled) reserve(server.subnet);
  const preferred = 10 * (networks.length + 1);
  const octet = used[preferred] === 0 ? preferred : used.indexOf(0);
  if (octet < 0) return { router: "", start: "", end: "" };
  const prefix = `192.168.${octet}.`;
  return { router: prefix + "1/24", start: prefix + "100", end: prefix + "200" };
}
