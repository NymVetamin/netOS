import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { Badge, Card, Empty, TableWrap } from "../ui";

// История ревизий и журнал аудита. Главная ценность — возможность вернуться к
// заведомо рабочей конфигурации, когда что-то пошло не так.
export function HistoryPage({ onRestored }: { onRestored: () => void }) {
  const [revisions, setRevisions] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [busy, setBusy] = useState(0);

  async function load() {
    const [r, a] = await Promise.all([api.revisions(), api.audit(60)]);
    setRevisions(r.revisions || []);
    setAudit(a.entries || []);
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="page-head">
        <h1>История</h1>
        <p>Ревизии конфигурации и журнал действий</p>
      </div>

      <Card title="Ревизии" subtitle="Каждое применение сохраняется отдельной версией" tight>
        {revisions.length === 0 ? (
          <Empty>История пуста</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>№</th>
                  <th>Создана</th>
                  <th>Автор</th>
                  <th>Комментарий</th>
                  <th>Состояние</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {revisions.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td className="faint">{formatTime(r.created_at)}</td>
                    <td>{r.author}</td>
                    <td className="dim">{r.comment || "—"}</td>
                    <td>{stateBadge(r.state)}</td>
                    <td style={{ textAlign: "right" }}>
                      {r.state !== "active" && (
                        <button
                          className="btn sm"
                          disabled={busy === r.id}
                          onClick={async () => {
                            setBusy(r.id);
                            try {
                              await api.restoreRevision(r.id);
                              onRestored();
                              await load();
                            } finally {
                              setBusy(0);
                            }
                          }}
                        >
                          Загрузить
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div style={{ padding: "0.8rem 1.1rem", borderTop: "1px solid var(--border)" }}>
          <span className="faint" style={{ fontSize: 12.5 }}>
            Кнопка «Загрузить» помещает ревизию в черновик — она не применяется, пока вы
            не нажмёте «Применить».
          </span>
        </div>
      </Card>

      <Card title="Журнал действий" tight>
        {audit.length === 0 ? (
          <Empty>Записей нет</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Пользователь</th>
                  <th>Действие</th>
                  <th>Объект</th>
                  <th>Подробности</th>
                  <th>Источник</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((e) => (
                  <tr key={e.id}>
                    <td className="faint">{formatTime(e.at)}</td>
                    <td>{e.user || "—"}</td>
                    <td>
                      <Badge tone={e.success ? "neutral" : "danger"}>
                        {actionLabel(e.action)}
                      </Badge>
                    </td>
                    <td className="mono faint">{e.target || "—"}</td>
                    <td className="dim">{e.detail || "—"}</td>
                    <td className="mono faint">{e.source_ip || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </>
  );
}

function stateBadge(state: string) {
  switch (state) {
    case "active":
      return <Badge tone="ok">применена</Badge>;
    case "rolled_back":
      return <Badge tone="danger">откачена</Badge>;
    case "draft":
      return <Badge tone="neutral">черновик</Badge>;
    case "superseded":
      return <Badge tone="neutral">заменена</Badge>;
    default:
      return <Badge tone="neutral">{state}</Badge>;
  }
}

function actionLabel(action: string): string {
  switch (action) {
    case "login":
      return "вход";
    case "apply":
      return "применение";
    case "confirm":
      return "подтверждение";
    case "rollback":
      return "откат";
    case "password_change":
      return "смена пароля";
    default:
      return action;
  }
}
