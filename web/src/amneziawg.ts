export const isWireGuardType = (type: string) => type === "wireguard" || type === "amneziawg";
export const wireGuardLabel = (type: string) => type === "amneziawg" ? "AmneziaWG" : "WireGuard";
export const wireGuardPrefix = (type: string) => type === "amneziawg" ? "awg" : "wg";

export type AmneziaOptions = Record<string, string | number | boolean>;
type Field = { key: string; native: string; kind: "number" | "range" | "signature" | "key" | "boolean"; max?: number };
export const amneziaFields: readonly Field[] = [
  { key: "jc", native: "Jc", kind: "number", max: 128 },
  { key: "jmin", native: "Jmin", kind: "number", max: 65507 },
  { key: "jmax", native: "Jmax", kind: "number", max: 65507 },
  ...[1, 2, 3, 4].map(n => ({ key: `s${n}`, native: `S${n}`, kind: "number" as const, max: 4096 })),
  ...[1, 2, 3, 4].map(n => ({ key: `h${n}`, native: `H${n}`, kind: "range" as const })),
  ...[1, 2, 3, 4, 5].map(n => ({ key: `i${n}`, native: `I${n}`, kind: "signature" as const })),
  { key: "header_protection_key", native: "HeaderProtectionKey", kind: "key" },
  { key: "content_padding_addition", native: "ContentPaddingAddition", kind: "range", max: 4096 },
  { key: "rekey_after_time", native: "RekeyAfterTime", kind: "range" },
  { key: "rekey_timeout", native: "RekeyTimeout", kind: "range" },
  { key: "reject_after_time", native: "RejectAfterTime", kind: "range" },
  { key: "keepalive_timeout", native: "KeepaliveTimeout", kind: "range" },
  { key: "max_handshake_attempts", native: "MaxHandshakeAttempts", kind: "range", max: 128 },
  { key: "random_trailers", native: "RandomTrailers", kind: "boolean" },
  { key: "disable_cookies", native: "DisableCookies", kind: "boolean" },
];
const nativeFields = new Map(amneziaFields.map(f => [f.native, f]));
export function newAmneziaOptions(): AmneziaOptions {
  return { jc: 3, jmin: 40, jmax: 70, s1: 16, s2: 17, s3: 18, s4: 19, h1: "100001", h2: "100002", h3: "100003", h4: "100004" };
}

export function amneziaRange(value: string, max = 4294967295): [number, number] {
  if (value.length > 21 || !/^\d+(?:-\d+)?$/.test(value)) throw new Error("Нужно число или диапазон a-b.");
  const [lo, hi = lo] = value.split("-").map(Number);
  if (lo > hi || hi > max || hi - lo >= 4294967295) throw new Error("Недопустимый диапазон AmneziaWG.");
  return [lo, hi];
}

function parseField(field: Field, value: string): string | number | boolean {
  if (field.kind === "number") {
    if (!/^\d+$/.test(value) || Number(value) > field.max!) throw new Error(`Некорректный ${field.native}.`);
    return Number(value);
  }
  if (field.kind === "boolean") {
    if (!["true", "false", "1", "0"].includes(value)) throw new Error(`Некорректный ${field.native}.`);
    return value === "true" || value === "1";
  }
  if (field.kind === "key") {
    if (value && (!/^[A-Za-z0-9+/]{43}=$/.test(value) || atob(value).length !== 32)) throw new Error("Некорректный ключ защиты заголовков.");
  } else if (field.kind === "range" && value) {
    const [lo, hi] = amneziaRange(value, field.max);
    if (!field.key.startsWith("h") && field.key !== "content_padding_addition" && lo === 0 && hi !== 0) throw new Error(`${field.native}: ноль нельзя смешивать с положительным таймаутом.`);
  } else if (field.kind === "signature") {
    validateSignature(value, field.native);
  }
  return value;
}

function validateSignature(value: string, name: string) {
  if (value.length > 131100) throw new Error(`${name}: слишком длинная сигнатура.`);
  let offset = 0, size = 0;
  while (offset < value.length) {
    const end = value.indexOf(">", offset + 1);
    if (value[offset] !== "<" || end < 0) throw new Error(`${name}: ожидается тег <...>.`);
    const tag = value.slice(offset + 1, end);
    if (tag === "t") size += 4;
    else if (/^b 0x(?:[a-fA-F0-9]{2})+$/.test(tag)) size += (tag.length - 4) / 2;
    else if (/^(r|rd|rc) \d+$/.test(tag)) {
      const [length] = amneziaRange(tag.slice(tag.indexOf(" ") + 1));
      size += length;
    } else throw new Error(`${name}: неизвестный или некорректный тег сигнатуры.`);
    if (size > 65507) throw new Error(`${name}: сигнатура превышает размер UDP-пакета.`);
    offset = end + 1;
  }
}

export function parseAmneziaOptions(iface: Record<string, string>): AmneziaOptions {
  const result: AmneziaOptions = {};
  for (const [name, value] of Object.entries(iface)) {
    const field = nativeFields.get(name);
    if (field) result[field.key] = parseField(field, value);
  }
  validateAmneziaOptions(result);
  return result;
}

export function validateAmneziaOptions(options: AmneziaOptions) {
  const ranges: [number, number][] = [];
  for (const field of amneziaFields) {
    const value = options[field.key];
    if (value !== undefined) parseField(field, String(value));
  }
  if (Number(options.jmin || 0) > Number(options.jmax || 0)) throw new Error("Jmin не должен превышать Jmax.");
  for (let i = 1; i <= 4; i++) {
    const range = amneziaRange(String(options[`h${i}`] || i));
    if (ranges.some(([lo, hi]) => range[0] <= hi && lo <= range[1])) throw new Error("Диапазоны H1–H4 не должны пересекаться.");
    ranges.push(range);
  }
  const key = options.header_protection_key;
  if (typeof key === "string" && key && [...atob(key)].some(c => c.charCodeAt(0) !== 0)) {
    for (let i = 1; i <= 4; i++) if (Number(options[`s${i}`] || 0) < 12) throw new Error("С ключом защиты заголовков S1–S4 должны быть не меньше 12.");
  }
  if (options.persistent_keepalive) amneziaRange(String(options.persistent_keepalive), 65535);
}

// Public fields always come from the current draft. The export response is used
// only to recover a masked key, never as a stale copy of all protocol settings.
export function amneziaClientParameters(options: AmneziaOptions = {}, savedParameters = ""): string {
  const values = { ...options };
  if (Object.hasOwn(values, "header_protection_key") && !values.header_protection_key) {
    values.header_protection_key = /^HeaderProtectionKey = (.*)$/m.exec(savedParameters)?.[1] || "";
  }
  validateAmneziaOptions(values);
  let text = "";
  for (const field of amneziaFields) {
    const value = values[field.key];
    if (value !== undefined && value !== "") text += `${field.native} = ${value}\n`;
  }
  return text;
}

export const amneziaNativeNames = new Set(nativeFields.keys());
