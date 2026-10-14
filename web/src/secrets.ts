// The mask is a placeholder, never a credential sent back to the API.
// Metadata belongs to the entity (stable ID), so reordering rows is harmless.
export function secretInput(owner: any, field: string) {
  const saved = !!owner?.secrets_set?.[field] || (field === "private_key" && !!owner?.reality_key_set);
  const entered = !!(owner?.[field] || owner?.config?.[field] || owner?.credentials?.[field]);
  const description = entered ? "Введено новое значение секрета" : saved
    ? "Секрет сохранён. Оставьте поле пустым, чтобы сохранить его, или введите новый."
    : "Секрет не задан";
  return { placeholder: saved ? "••••••••" : "Не задан", title: description, "aria-description": description };
}
