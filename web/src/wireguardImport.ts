import { AMNEZIAWG_NUMBERS, AMNEZIAWG_TEXTS, amneziaWGNativeName } from "./amneziawg";
// Import data only. wg-quick commands are never executed.
export function parseWireGuardConfig(text: string) {
  const sections: Record<string, Record<string, string>> = {};
  let section = "";
  for (const raw of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.split("#", 1)[0].trim();
    if (!line) continue;
    if (line.startsWith("[")) {
      if (line !== "[Interface]" && line !== "[Peer]") throw new Error("Поддерживаются только секции [Interface] и [Peer].");
      section = line.slice(1, -1);
      if (sections[section]) throw new Error("Для канала нужен один Interface и один Peer.");
      sections[section] = {};
      continue;
    }
    const equal = line.indexOf("=");
    if (!section || equal < 1) throw new Error("Некорректная строка конфигурации WireGuard.");
    const key = line.slice(0, equal).trim(), value = line.slice(equal + 1).trim();
    if (Object.prototype.hasOwnProperty.call(sections[section], key)) throw new Error(`Параметр ${key} указан повторно.`);
    sections[section][key] = value;
  }
  const iface = sections.Interface, peer = sections.Peer;
  if (!iface || !peer) throw new Error("Нужны секции [Interface] и [Peer].");
  const warnings: string[] = [];
  // AmneziaVPN profiles carry obfuscation in [Interface]; they make the
  // channel an AmneziaWG channel. Ranges are checked by the backend.
  const amnezia: Record<string, number | string> = {};
  for (const key of [...AMNEZIAWG_NUMBERS, ...AMNEZIAWG_TEXTS]) {
    const native = amneziaWGNativeName(key);
    const value = iface[native];
    if (value === undefined) continue;
    if ((AMNEZIAWG_NUMBERS as readonly string[]).includes(key)) {
      if (!/^\d+$/.test(value)) throw new Error(`Некорректный ${native}.`);
      amnezia[key] = Number(value);
    } else if (value !== "") amnezia[key] = value;
  }
  // Sets keep the unknown-key check O(1) per key of the file.
  const ifaceKeys = new Set(["Address", "PrivateKey", "MTU", ...[...AMNEZIAWG_NUMBERS, ...AMNEZIAWG_TEXTS].map(amneziaWGNativeName)]);
  const peerKeys = new Set(["PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"]);
  for (const [values, supported] of [[iface, ifaceKeys], [peer, peerKeys]] as const) {
    for (const key of Object.keys(values)) if (!supported.has(key)) warnings.push(`${key} не перенесён: netOS управляет этой настройкой отдельно.`);
  }
  const list = (value = "") => value.split(",").map(v => v.trim()).filter(Boolean);
  const ipv4 = (value: string) => {
    const [address, mask, extra] = value.split("/");
    return extra === undefined && /^\d+$/.test(mask || "") && Number(mask) <= 32 && address.split(".").length === 4 && address.split(".").every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  };
  const addresses = list(iface.Address);
  const v4Addresses = addresses.filter(v => !v.includes(":"));
  if (v4Addresses.length !== 1 || !ipv4(v4Addresses[0])) throw new Error("Нужен один IPv4-адрес туннеля с маской.");
  if (addresses.some(v => v.includes(":"))) warnings.push("IPv6 не перенесён: исходящий канал netOS использует IPv4.");
  const key = (value: string, label: string) => {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(value || "") || atob(value).length !== 32) throw new Error(`Некорректный или отсутствующий ${label}.`);
    return value;
  };
  const number = (value: string | undefined, fallback: number, min: number, max: number, label: string) => {
    if (value === undefined) return fallback;
    if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(`Некорректный ${label}.`);
    return Number(value);
  };
  if (!/^(\[[^\]\s]+\]|[^:\s]+):\d+$/.test(peer.Endpoint || "")) throw new Error("Нужен Endpoint в формате host:port.");
  number(peer.Endpoint.slice(peer.Endpoint.lastIndexOf(":") + 1), 0, 1, 65535, "порт Endpoint");
  const config: Record<string, unknown> = {
    address: v4Addresses[0], private_key: key(iface.PrivateKey, "приватный ключ"),
    peer_public_key: key(peer.PublicKey, "публичный ключ сервера"), endpoint: peer.Endpoint,
    allowed_ips: ["0.0.0.0/0"], mtu: number(iface.MTU, 1420, 576, 9000, "MTU"),
    persistent_keepalive: number(peer.PersistentKeepalive, 0, 0, 65535, "PersistentKeepalive"),
  };
  // Omit an absent PSK: the API preserves redacted secrets only for present keys.
  if (peer.PresharedKey) config.preshared_key = key(peer.PresharedKey, "PresharedKey");
  if (Object.keys(amnezia).length) config.amneziawg = amnezia;
  return { config, warnings };
}
