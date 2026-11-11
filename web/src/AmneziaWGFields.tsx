import { amneziaFields, AmneziaOptions } from "./amneziawg";
import { secretInput } from "./secrets";
import { Field, Switch } from "./ui";

export function AmneziaWGFields({ owner, update }: { owner: any; update: (options: AmneziaOptions) => void }) {
  const options: AmneziaOptions = owner.config?.amnezia || {};
  const set = (key: string, value: string | number | boolean) => update({ ...options, [key]: value });
  return <details className="advanced"><summary>Параметры AmneziaWG</summary>
    <p className="hint">Для подключения значения должны соответствовать профилю сервера. H1–H4 — разные числа или непересекающиеся диапазоны. I1–I5 — сигнатуры пакетов. Расширенные параметры поддерживает AmneziaWG 3.1.</p>
    <div className="form-grid">{amneziaFields.map(field => <Field key={field.key} label={field.native}>
      {field.kind === "boolean" ? <Switch checked={!!options[field.key]} label={field.native} onChange={value => set(field.key, value)} />
        : <input className="mono" type={field.kind === "number" ? "number" : field.kind === "key" ? "password" : "text"}
          min={field.kind === "number" ? 0 : undefined} max={field.max}
          autoComplete="off" spellCheck={false} maxLength={field.kind === "signature" ? 131100 : 44}
          {...(field.kind === "key" ? secretInput({ secrets_set: owner.secrets_set, "amnezia.header_protection_key": options.header_protection_key }, "amnezia.header_protection_key") : {})}
          value={String(options[field.key] ?? "")} onChange={e => set(field.key, field.kind === "number" ? Number(e.target.value) : e.target.value)} />}
      {field.kind === "key" && (Object.hasOwn(options, field.key) || owner.secrets_set?.["amnezia.header_protection_key"]) && <button type="button" className="btn ghost sm" onClick={() => { const next = { ...options }; delete next[field.key]; update(next); }}>Убрать ключ защиты заголовков</button>}
    </Field>)}<Field label="PersistentKeepalive — число или диапазон, с"><input className="mono" maxLength={21} placeholder={String(owner.config?.persistent_keepalive ?? 25)} value={String(options.persistent_keepalive ?? "")} onChange={e => set("persistent_keepalive", e.target.value)} /></Field></div>
  </details>;
}
