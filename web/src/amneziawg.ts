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
