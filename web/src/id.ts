let fallbackSequence = 0;

// Keep persistent IDs unique even when an add button is clicked more than once
// inside the same millisecond.
export function newID(prefix: string): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  fallbackSequence = (fallbackSequence + 1) % 1_000_000;
  return `${prefix}-${Date.now().toString(36)}-${fallbackSequence.toString(36)}`;
}
