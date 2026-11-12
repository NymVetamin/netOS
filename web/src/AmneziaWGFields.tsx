import { AMNEZIAWG_NUMBERS, AMNEZIAWG_TEXTS, amneziaWGNativeName } from "./amneziawg";
import { Field } from "./ui";

const HINTS: Record<string, string> = {
  jc: "Число мусорных пакетов перед рукопожатием, 0–128",
  jmin: "Минимальный размер мусорного пакета", jmax: "Максимальный размер мусорного пакета",
  s1: "Дополнение начала рукопожатия", s2: "Дополнение ответа; S1 + 56 не должно равняться S2",
  s3: "Дополнение cookie", s4: "Дополнение пакетов данных",
  h1: "Тип начала рукопожатия: число или диапазон a-b", h2: "Тип ответа рукопожатия", h3: "Тип cookie", h4: "Тип пакета данных",
  i1: "Сигнатура первого пакета, например <b 0x…><r 16><t>",
};

// Parameters must match the server exactly; the backend validates the ranges.
export function AmneziaWGFields({ value, onChange }: { value: any; onChange: (next: any) => void }) {
  const set = (key: string, raw: string, numeric: boolean) => {
    const next = { ...value };
    if (numeric) next[key] = raw === "" ? 0 : Number(raw);
    else if (raw.trim() === "") delete next[key];
    else next[key] = raw.trim();
    onChange(next);
  };
  return <>
    {AMNEZIAWG_NUMBERS.map(key => <Field key={key} label={amneziaWGNativeName(key)} hint={HINTS[key]}>
      <input aria-label={`AmneziaWG ${amneziaWGNativeName(key)}`} type="number" min={0} value={value?.[key] ?? 0} onChange={e => set(key, e.target.value, true)} />
    </Field>)}
    {AMNEZIAWG_TEXTS.map(key => <Field key={key} wide={key.startsWith("i")} label={amneziaWGNativeName(key)} hint={HINTS[key]}>
      <input aria-label={`AmneziaWG ${amneziaWGNativeName(key)}`} className="mono" value={value?.[key] ?? ""} onChange={e => set(key, e.target.value, false)} />
    </Field>)}
  </>;
}
