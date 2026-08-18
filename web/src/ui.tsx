// Базовые элементы интерфейса. Держим их в одном месте, чтобы страницы
// занимались данными, а не оформлением.

import { ReactNode } from "react";

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
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label className="switch">
      <input
        type="checkbox"
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
