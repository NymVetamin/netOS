// Базовые элементы интерфейса. Держим их в одном месте, чтобы страницы
// занимались данными, а не оформлением.

import { Children, cloneElement, isValidElement, ReactElement, ReactNode, useEffect, useId, useRef, useState } from "react";
import { formatBitrate } from "./api";
import { CARD_ICONS, Icon, IconName } from "./icons";

function labelNestedControls(node: ReactNode, label: string, hintID?: string): ReactNode {
  return Children.map(node, (child) => {
    if (!isValidElement(child)) return child;
    const element = child as ReactElement<any>;
    if (typeof element.type === "string" && ["input", "select", "textarea"].includes(element.type)) {
      return cloneElement(element, {
        "aria-label": element.props["aria-label"] || label,
        "aria-describedby": element.props["aria-describedby"] || hintID,
      });
    }
    if (element.props.children == null) return element;
    return cloneElement(element, {
      children: labelNestedControls(element.props.children, label, hintID),
    });
  });
}

export function Card({
  title,
  subtitle,
  actions,
  children,
  tight,
  split,
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  tight?: boolean;
  // Карточка из нескольких частей: каждая .card-part рисует свою рамку, между
  // ними стоят подзаголовки .card-sub.
  split?: boolean;
}) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2>{CARD_ICONS[title] && <Icon name={CARD_ICONS[title]} />}{title}</h2>}
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </header>
      )}
      <div className={split ? "card-body split" : tight ? "card-body tight" : "card-body"}>{children}</div>
    </section>
  );
}

export function Tile({
  label,
  value,
  note,
  tone,
  small,
  icon,
}: {
  icon?: IconName;
  label: string;
  value: ReactNode;
  note?: string;
  tone?: "ok" | "warn" | "danger";
  small?: boolean;
}) {
  const body = <>
    <div className="label">
      {tone && <span className="dot" style={{ color: `var(--${tone})` }} />}
      {label}
    </div>
    <div className={small ? "value small" : "value"}>{value}</div>
    {note && <div className="note">{note}</div>}
  </>;
  return icon
    ? <div className="tile with-icon"><Icon name={icon} className="tile-icon" /><div>{body}</div></div>
    : <div className="tile">{body}</div>;
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "ok" | "warn" | "danger" | "neutral" | "accent";
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Field({
  label,
  hint,
  wide,
  children,
}: {
  label: string;
  hint?: string;
  // Длинное значение: список серверов, адрес с путём.
  wide?: boolean;
  children: ReactNode;
}) {
  const generatedID = useId();
  const labelID = `${generatedID}-label`;
  const hintID = hint ? `${generatedID}-hint` : undefined;
  const element = isValidElement(children) ? (children as ReactElement<{ id?: string; "aria-describedby"?: string }>) : null;
  const isControl = element != null && typeof element.type === "string" && ["input", "select", "textarea"].includes(element.type);
  const controlID = isControl ? element.props.id || generatedID : undefined;
  return (
    <div className={wide ? "field wide" : "field"}>
      <label id={labelID} className="field-label" htmlFor={controlID}>{label}</label>
      {isControl
        ? cloneElement(element, { id: controlID, "aria-describedby": hintID })
        : <div className="field-control" role="group" aria-labelledby={labelID} aria-describedby={hintID}>{labelNestedControls(children, label, hintID)}</div>}
      {hint && <div id={hintID} className="hint">{hint}</div>}
    </div>
  );
}

// Подпись над полем, у которого уже есть своё имя в aria-label. Это не <label>:
// имя поля для вспомогательных технологий и проверок панели остаётся прежним.
export function Cap({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? "field wide" : "field"}>
      <div className="field-label" aria-hidden="true">{label}</div>
      {children}
    </div>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  ariaLabel,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  ariaLabel?: string;
  disabled?: boolean;
}) {
  return (
    <label className="switch">
      <input
        type="checkbox"
        aria-label={ariaLabel}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="track" />
      <span>{label}</span>
    </label>
  );
}

export function Notice({
  tone,
  title,
  children,
  actions,
}: {
  tone: "info" | "warn" | "danger";
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  const icon = tone === "danger" ? "!" : tone === "warn" ? "!" : "i";
  return (
    <div className={`notice ${tone}`}>
      <strong aria-hidden="true">{icon}</strong>
      <div className="body">
        <div className="title">{title}</div>
        {children && <div className="text">{children}</div>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

// Строки записей. Любая запись панели — сервер, устройство, сегмент, правило —
// это одна строка; настройки раскрываются под ней. Столбцы у всех таблиц
// панели общие: имя, три столбца, состояние и переключатель, поэтому они
// стоят на одной вертикали на любой странице.
//
// Раскрытие — системный <details>, а не состояние React: содержимое остаётся
// в документе и свёрнутым, так что поиск по странице его находит, а проверки
// панели видят те же поля, что и раньше.
export function Rows({ cols, toggle, children }: { cols: string[]; toggle?: string; children: ReactNode }) {
  return (
    <div className="xrows">
      <div className="xhead">
        <span />
        {[0, 1, 2, 3, 4].map((i) => <span key={i}>{cols[i] || ""}</span>)}
        <span>{toggle || ""}</span>
      </div>
      {children}
    </div>
  );
}

// Только что созданная запись открывается сразу: её добавили, чтобы настроить.
const created = new Set<string>();
export function openOnCreate(id: string) {
  created.add(id);
  return id;
}

export function Row({
  id,
  cells,
  toggle,
  children,
  className,
  icon,
  as: Tag = "div",
  lazyBody = false,
  ...rest
}: {
  id?: string;
  cells: ReactNode[];
  // Значок перед именем записи: тип канала, сервера, порта.
  icon?: IconName;
  toggle?: ReactNode;
  children?: ReactNode;
  className?: string;
  as?: "div" | "form";
  lazyBody?: boolean;
  [attribute: string]: unknown;
}) {
  const details = useRef<HTMLDetailsElement>(null);
  const [visited, setVisited] = useState(false);
  useEffect(() => {
    if (id && created.delete(id) && details.current) {
      details.current.open = true;
      setVisited(true);
    }
  }, [id]);
  const summary = [0, 1, 2, 3, 4].map((i) => i === 0 && icon
    ? <span key={i} className="xname"><Icon name={icon} />{cells[i]}</span>
    : <span key={i}>{cells[i] ?? ""}</span>);
  const Wrapper = Tag as "div";
  return (
    <Wrapper className={`xrow ${className || ""}`} {...rest}>
      {/* Переключатель в документе первый: это «главный переключатель записи». */}
      {toggle && <div className="xsw">{toggle}</div>}
      {children
        ? <details className="xd" ref={details} onToggle={lazyBody ? e => { if (e.currentTarget.open) setVisited(true); } : undefined}><summary className="xsum">{summary}</summary><div className="xbody">{!lazyBody || visited ? children : null}</div></details>
        : <div className="xsum">{summary}</div>}
    </Wrapper>
  );
}

// Одна кнопка «Добавить» с выбором типа вместо ряда из десятка кнопок.
export function AddMenu({
  label,
  items,
}: {
  label: string;
  items: { label: string; ariaLabel?: string; note?: string; icon?: IconName; disabled?: boolean; onSelect: () => void }[];
}) {
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const close = (event: Event) => {
      if (!menu.current) return;
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !menu.current.contains(event.target as Node)) menu.current.open = false;
    };
    document.addEventListener("click", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", close);
    };
  }, []);
  return (
    <details className="addmenu" ref={menu}>
      <summary className="btn primary">{label}</summary>
      <div className="menu">
        {items.map((item) => (
          <button
            type="button"
            key={item.ariaLabel || item.label}
            aria-label={item.ariaLabel}
            disabled={item.disabled}
            onClick={() => { if (menu.current) menu.current.open = false; item.onSelect(); }}
          >
            {item.icon && <Icon name={item.icon} />}
            <span>
              {item.label}
              {item.note && <small>{item.note}</small>}
            </span>
          </button>
        ))}
      </div>
    </details>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Spinner() {
  return <span className="spinner" role="status" aria-label="загрузка" />;
}

// Таблица с горизонтальной прокруткой: на узком экране широкие таблицы
// маршрутов и правил иначе растягивают всю страницу.
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="table-wrap">{children}</div>;
}

// Скорость всегда с направлением и единицами: «↓ 312.4 Мбит/с  ↑ 94.1 Мбит/с».
// Голые числа со стрелками читались неоднозначно — непонятно, мегабиты это
// или мегабайты.
export function Speed({ down, up }: { down: number; up: number }) {
  const part = (arrow: string, bps: number) => {
    const [value, unit] = splitUnit(formatBitrate(bps));
    return <span>{arrow} {value} <span className="unit">{unit}</span></span>;
  };
  return <span className="speed">{part("↓", down)}{part("↑", up)}</span>;
}

function splitUnit(text: string): [string, string] {
  const i = text.lastIndexOf(" ");
  return [text.slice(0, i), text.slice(i + 1)];
}
