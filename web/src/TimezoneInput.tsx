import { useId, useState } from "react";
// IANA suggestions exported from Node Intl.supportedValuesOf("timeZone"), plus UTC.
// Keep free input for aliases and zones supported by the router but absent here.
import timezones from "./timezones.json";

export function TimezoneInput({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const query = value.trim().toLowerCase().replace(/ /g, "_");
  const matches = query ? timezones.filter(zone => zone.toLowerCase().split("/").some(part => part.startsWith(query)) || zone.toLowerCase().startsWith(query)).slice(0, 10) : [];
  const visible = open && matches.length > 0;
  const choose = (zone: string) => { onChange(zone); setOpen(false); setActive(-1); };
  return <div className="timezone-input">
    <input type="text" role="combobox" aria-label="Часовой пояс" autoComplete="off"
      aria-autocomplete="list" aria-expanded={visible} aria-controls={visible ? id : undefined}
      aria-activedescendant={visible && active >= 0 ? `${id}-${active}` : undefined}
      value={value} onChange={e => { onChange(e.target.value); setActive(-1); setOpen(true); }}
      onFocus={() => { setOpen(true); setActive(-1); }} onBlur={() => setOpen(false)}
      onKeyDown={e => {
        if (e.key === "Escape") { setOpen(false); setActive(-1); }
        if ((e.key === "ArrowDown" || e.key === "ArrowUp") && matches.length) {
          e.preventDefault(); setOpen(true);
          setActive(previous => e.key === "ArrowDown" ? (previous + 1) % matches.length : (previous <= 0 ? matches.length - 1 : previous - 1));
        }
        if (e.key === "Enter" && visible && active >= 0) { e.preventDefault(); choose(matches[active]); }
      }} />
    {visible && <ul id={id} className="timezone-options" role="listbox" aria-label="Часовые пояса">
      {matches.map((zone, index) => <li key={zone} id={`${id}-${index}`} role="option" aria-selected={active === index}
        onMouseDown={e => e.preventDefault()} onClick={() => choose(zone)}>{zone}</li>)}
    </ul>}
  </div>;
}
