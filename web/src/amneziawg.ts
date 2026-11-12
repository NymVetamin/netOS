// AmneziaWG parameter names shared by the form and the .conf import.

// Junk packets before the handshake; headers and padding stay standard until
// the values of the server are entered or imported (they must match it).
export const AMNEZIAWG_DEFAULTS = { jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0, h1: "1", h2: "2", h3: "3", h4: "4" };

export const AMNEZIAWG_NUMBERS = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"] as const;
export const AMNEZIAWG_TEXTS = ["h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"] as const;

// Native spelling in AmneziaVPN profiles: Jc, Jmin, Jmax, S1…, H1…, I1….
export function amneziaWGNativeName(key: string): string {
  return ({ jc: "Jc", jmin: "Jmin", jmax: "Jmax" } as Record<string, string>)[key] || key.toUpperCase();
}

// A new server gets its own random obfuscation, like AmneziaVPN: distinct
// header types and paddings make every router's traffic look different.
// Clients receive these values in their profiles.
export function randomAmneziaWGParams() {
  const random = (lo: number, hi: number) => lo + (crypto.getRandomValues(new Uint32Array(1))[0] % (hi - lo + 1));
  const jmin = random(10, 50);
  const s1 = random(15, 150);
  let s2 = random(15, 150);
  while (s1 + 56 === s2) s2 = random(15, 150); // equal sizes would unmask the handshake
  const headers = new Set<number>();
  while (headers.size < 4) headers.add(random(5, 2147483647));
  const [h1, h2, h3, h4] = [...headers].map(String);
  return { jc: random(3, 10), jmin, jmax: jmin + random(30, 950), s1, s2, h1, h2, h3, h4 };
}

// [Interface] lines of a client profile; mirrors config.AmneziaWGParams
// NativeLines: numbers always, standard header types by default, only the
// signatures that are set (the native tools reject an empty one).
export function amneziaWGProfileLines(params: any): string {
  if (!params) return "";
  const numbers = AMNEZIAWG_NUMBERS.map(key => `${amneziaWGNativeName(key)} = ${Number(params[key] || 0)}\n`);
  const headers = ["h1", "h2", "h3", "h4"].map((key, i) => `${amneziaWGNativeName(key)} = ${params[key] || i + 1}\n`);
  const signatures = ["i1", "i2", "i3", "i4", "i5"].filter(key => params[key]).map(key => `${amneziaWGNativeName(key)} = ${params[key]}\n`);
  return [...numbers, ...headers, ...signatures].join("");
}
