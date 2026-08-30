// Базовые элементы интерфейса. Держим их в одном месте, чтобы страницы
// занимались данными, а не оформлением.

import { Children, cloneElement, isValidElement, ReactElement, ReactNode, useId } from "react";

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
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  tight?: boolean;
}) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </header>
      )}
      <div className={tight ? "card-body tight" : "card-body"}>{children}</div>
    </section>
  );
}

export function Tile({
  label,
  value,
  note,
  tone,
  small,
}: {
  label: string;
  value: ReactNode;
  note?: string;
  tone?: "ok" | "warn" | "danger";
  small?: boolean;
}) {
  return (
    <div className="tile">
      <div className="label">
        {tone && <span className="dot" style={{ color: `var(--${tone})` }} />}
        {label}
      </div>
      <div className={small ? "value small" : "value"}>{value}</div>
      {note && <div className="note">{note}</div>}
    </div>
  );
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
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  const generatedID = useId();
  const labelID = `${generatedID}-label`;
  const hintID = hint ? `${generatedID}-hint` : undefined;
  const element = isValidElement(children) ? (children as ReactElement<{ id?: string; "aria-describedby"?: string }>) : null;
  const isControl = element != null && typeof element.type === "string" && ["input", "select", "textarea"].includes(element.type);
  const controlID = isControl ? element.props.id || generatedID : undefined;
  return (
    <div className="field">
      <label id={labelID} className="field-label" htmlFor={controlID}>{label}</label>
      {isControl
        ? cloneElement(element, { id: controlID, "aria-describedby": hintID })
        : <div className="field-control" role="group" aria-labelledby={labelID} aria-describedby={hintID}>{labelNestedControls(children, label, hintID)}</div>}
      {hint && <div id={hintID} className="hint">{hint}</div>}
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
