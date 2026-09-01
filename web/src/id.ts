let fallbackSequence = 0;

// Keep persistent IDs unique even when an add button is clicked more than once
// inside the same millisecond.
export function newID(prefix: string): string {
  // Часть ID становится именем Linux-интерфейса. Самый жёсткий случай —
  // PPPoE/L2TP: `ppp-${id}` обязан поместиться в IFNAMSIZ (15 символов).
  // Семь base36-символов дают более 78 млрд вариантов и оставляют `wan-*`
  // ровно в допустимой длине; UUID здесь делал каждый новый WAN невалидным.
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const random = crypto.getRandomValues(new Uint32Array(1))[0];
    return `${prefix}-${random.toString(36).padStart(7, "0")}`;
  }
  fallbackSequence = (fallbackSequence + 1) % 1_000_000;
  const mixed = (Date.now() ^ fallbackSequence) >>> 0;
  return `${prefix}-${mixed.toString(36).padStart(7, "0")}`;
}
