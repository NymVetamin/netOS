import { PlanResponse } from "./api";

export function PlanPreview({ plan }: { plan: PlanResponse }) {
  const changes = plan.changes;
  const actions = plan.actions || [];
  return <section className="plan-preview" aria-label="План изменений">
    <strong>Что изменится</strong>
    {changes === undefined ? <p className="dim">Сервер предоставил только технический план.</p>
      : changes.length === 0 ? <p className="dim">Различий в настройках нет.{actions.length > 0 ? " Технический план содержит операции подсистем." : " Технический план пуст."}</p>
      : <ul className="plan-changes">{changes.map((change) => <li key={`${change.path}:${change.kind}`}>
        <div className="plan-change-label">{change.kind === "add" ? "Добавить: " : change.kind === "remove" ? "Удалить: " : ""}{change.label}</div>
        {change.kind !== "add" && change.kind !== "remove" && <div className="plan-change-values">
          {change.before === "Скрыто" && change.after === "Скрыто"
            ? "Значение изменено · содержимое скрыто"
            : <><span><span className="dim">Было: </span>{change.before}</span><span aria-hidden="true"> → </span><span><span className="dim">Станет: </span>{change.after}</span></>}
        </div>}
      </li>)}</ul>}
    {plan.needs_confirm !== undefined && <p className={plan.needs_confirm ? "plan-confirm" : "dim"}>
      {plan.needs_confirm ? "Потребуется подтверждение. Возможна потеря связи с панелью; без подтверждения настройки автоматически откатятся."
        : "Подтверждение после применения не потребуется."}
    </p>}
    {changes && changes.length > 0 && actions.length === 0 && <p className="dim">Изменения настроек будут сохранены. Технический план не содержит отдельных операций; штатная проверка и применение конфигурации сохраняются.</p>}
    {actions.length > 0 && <details><summary>Технические подробности · {actions.length}</summary>
      <ul>{actions.map((action, index) => <li key={index}>{action.disruptive ? "⚠ " : ""}{action.subsystem}: {action.kind} — {action.target}{action.detail ? ` (${action.detail})` : ""}</li>)}</ul>
    </details>}
  </section>;
}
