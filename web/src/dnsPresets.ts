export type DNSPreset = {
  id: string; name: string; ip: string; tls: string; doh: string; doq?: string;
};

// Public endpoints: Cloudflare / Google Public DNS / Quad9 service docs and
// https://adguard-dns.io/en/public-dns.html. DoQ is not inferred from DoH3.
export const DNS_PRESETS: DNSPreset[] = [
  { id: "cloudflare", name: "Cloudflare", ip: "1.1.1.1", tls: "cloudflare-dns.com", doh: "https://1.1.1.1/dns-query" },
  { id: "google", name: "Google", ip: "8.8.8.8", tls: "dns.google", doh: "https://dns.google/dns-query" },
  { id: "quad9", name: "Quad9", ip: "9.9.9.9", tls: "dns.quad9.net", doh: "https://dns.quad9.net/dns-query", doq: "quic://dns.quad9.net" },
  { id: "adguard", name: "AdGuard — блокировка рекламы", ip: "94.140.14.14", tls: "dns.adguard-dns.com", doh: "https://dns.adguard-dns.com/dns-query", doq: "quic://dns.adguard-dns.com" },
  { id: "adguard-unfiltered", name: "AdGuard — без фильтрации", ip: "94.140.14.140", tls: "unfiltered.adguard-dns.com", doh: "https://unfiltered.adguard-dns.com/dns-query", doq: "quic://unfiltered.adguard-dns.com" },
];

export function presetAddress(p: DNSPreset, type: string, provider: string): string {
  if (type === "plain") return p.ip;
  if (type === "dot") return provider === "unbound" ? `${p.ip}#${p.tls}` : `tls://${p.tls}`;
  if (type === "doh") return p.doh;
  if (type === "doq") return p.doq || "";
  return "";
}

export function presetLabel(p: DNSPreset, type: string): string {
  const address = type === "dot" ? p.ip : presetAddress(p, type, "");
  return `${address} (${p.name})`;
}

export function matchDNSPreset(up: { type: string; address: string }): DNSPreset | undefined {
  const address = (up.address || "").trim();
  return DNS_PRESETS.find(p => {
    if (up.type === "plain") return address === p.ip;
    if (up.type === "dot") return [p.ip, p.tls, `tls://${p.tls}`, `${p.ip}#${p.tls}`, `${p.ip}@853#${p.tls}`].includes(address);
    if (up.type === "doh") return address === p.doh || address === `https://${p.tls}/dns-query`;
    return up.type === "doq" && !!p.doq && [p.doq, p.tls].includes(address);
  });
}
