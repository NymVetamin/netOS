import { useContext } from "react";
import { PermissionContext } from "../permissions";
import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { Badge, Card, Empty, Notice, Spinner, TableWrap } from "../ui";
import { Icon } from "../icons";

// История ревизий. Главная ценность — возможность вернуться к заведомо рабочей
// конфигурации, когда что-то пошло не так. Действия администраторов показывает
// журнал «Система» в разделе «Диагностика».
export function HistoryPage({ onRestored }: { onRestored: () => void }) {
  const session = useContext(PermissionContext);
  const [revisions, setRevisions] = useState<any[]>([]);
  const [busy, setBusy] = useState(0);
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    setLoadError("");
    try {
      const r = await api.revisions();
      setRevisions(r.revisions || []);
    } catch (cause) {
      setLoadError(cause instanceof Error ? cause.message : "Не удалось загрузить историю");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="page-head">
        <h1><Icon name="history" />История</h1>
        <p>Ревизии конфигурации</p>
      </div>

      {error && <Notice tone="danger" title="Не удалось загрузить ревизию">{error}</Notice>}
      {loadError && (
        <Notice tone="danger" title="Не удалось загрузить историю">
          <p>{loadError}</p>
          <button className="btn sm" onClick={() => void load()}>Повторить загрузку</button>
        </Notice>
      )}

      {loading ? <Card><div className="loading-state"><Spinner /> Загружаем историю…</div></Card> : <>
      <Card title="Ревизии" subtitle="Каждое применение сохраняется отдельной версией" tight>
        {loadError ? null : revisions.length === 0 ? (
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
                      {(!session || session.role === "admin") && r.state !== "active" && (
                        <button
                          className="btn sm"
                          disabled={busy === r.id}
                          onClick={async () => {
                            setBusy(r.id);
                            setError("");
                            try {
                              await api.restoreRevision(r.id);
                              onRestored();
                              await load();
                            } catch (cause) {
                              setError(cause instanceof Error ? cause.message : "Не удалось загрузить ревизию");
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

      </>}
    </>
  );
}

function stateBadge(state: string) {
  switch (state) {
    case "active":
      return <Badge tone="ok">применена</Badge>;
    case "rolled_back":
      return <Badge tone="danger">откачена</Badge>;
    case "failed":
      return <Badge tone="danger">ошибка применения</Badge>;
    case "draft":
      return <Badge tone="neutral">черновик</Badge>;
    case "superseded":
      return <Badge tone="neutral">заменена</Badge>;
    default:
      return <Badge tone="neutral">{state}</Badge>;
  }
}
