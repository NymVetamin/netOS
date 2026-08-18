import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

// Маршрутизация: куда роутер отправляет пакеты и по какому признаку выбирает
// таблицу. На этом же механизме позже будет построен выбор VPN-канала для
// каждого клиента, поэтому таблицы и правила показаны явно, а не спрятаны.
export function RoutingPage({ config, patch }: { config: any; patch: Patch }) {
  const [live, setLive] = useState<{ routes: string; rules: string } | null>(null);

  useEffect(() => {
    const load = () => api.routes().then(setLive).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const routing = config.routing || { static: [], tables: [], rules: [] };
  const tableNames = ["main", ...(routing.tables || []).map((t: any) => t.name)];

  return (
    <>
      <div className="page-head">
        <h1>Маршрутизация</h1>
        <p>Статические маршруты, дополнительные таблицы и правила выбора таблиц</p>
      </div>

      <Card
        title="Статические маршруты"
        subtitle="Маршруты, добавленные вручную поверх тех, что появляются сами"
        tight
        actions={
          <button
            className="btn sm"
            onClick={() =>
              patch((d) => {
                d.routing = d.routing || { static: [], tables: [], rules: [] };
                d.routing.static = d.routing.static || [];
                d.routing.static.push({
                  id: "route-" + Date.now(),
                  name: "Маршрут",
                  enabled: true,
                  destination: "",
                  gateway: "",
                  metric: 0,
                  table: "",
                  type: "unicast",
                });
              })
            }
          >
            Добавить
          </button>
        }
      >
        {(routing.static || []).length === 0 ? (
          <Empty>Статических маршрутов нет</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Название</th>
                  <th>Куда</th>
                  <th>Через шлюз</th>
                  <th>Или интерфейс</th>
                  <th>Метрика</th>
                  <th>Таблица</th>
                  <th>Вкл.</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {routing.static.map((r: any, idx: number) => (
                  <tr key={r.id}>
                    <td>
                      <input
                        type="text"
                        style={{ width: 130 }}
                        value={r.name}
                        onChange={(e) => patch((d) => (d.routing.static[idx].name = e.target.value))}
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        className="mono"
                        style={{ width: 150 }}
                        placeholder="10.0.0.0/8 или default"
                        value={r.destination}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].destination = e.target.value))
                        }
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        className="mono"
                        style={{ width: 130 }}
                        value={r.gateway || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].gateway = e.target.value))
                        }
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        className="mono"
                        style={{ width: 100 }}
                        value={r.interface || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].interface = e.target.value))
                        }
                      />
                    </td>
                    <td>
                      <input
                        type="number"
                        style={{ width: 80 }}
                        value={r.metric || 0}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].metric = Number(e.target.value)))
                        }
                      />
                    </td>
                    <td>
                      <select
                        value={r.table || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].table = e.target.value))
                        }
                      >
                        <option value="">основная</option>
                        {(routing.tables || []).map((t: any) => (
                          <option key={t.id} value={t.name}>
                            {t.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <Switch
                        checked={r.enabled}
                        label=""
                        onChange={(v) => patch((d) => (d.routing.static[idx].enabled = v))}
                      />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost sm"
                        onClick={() =>
                          patch(
                            (d) =>
                              (d.routing.static = d.routing.static.filter(
                                (x: any) => x.id !== r.id,
                              )),
                          )
                        }
                      >
                        Удалить
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Card
        title="Дополнительные таблицы"
        subtitle="Отдельные наборы маршрутов: например, свой выход в интернет для части клиентов"
        tight
        actions={
          <button
            className="btn sm"
            onClick={() =>
              patch((d) => {
                d.routing = d.routing || { static: [], tables: [], rules: [] };
                d.routing.tables = d.routing.tables || [];
                const n = d.routing.tables.length + 1;
                d.routing.tables.push({
                  id: "table-" + Date.now(),
                  name: "netos-t" + n,
                  number: 100 + n,
                  system: false,
                });
              })
            }
          >
            Добавить
          </button>
        }
      >
        {(routing.tables || []).length === 0 ? (
          <Empty>
            Дополнительных таблиц нет. Пока весь трафик идёт по основной таблице.
          </Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Номер</th>
                  <th>Комментарий</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {routing.tables.map((t: any, idx: number) => (
                  <tr key={t.id}>
                    <td>
                      <input
                        type="text"
                        className="mono"
                        style={{ width: 150 }}
                        value={t.name}
                        disabled={t.system}
                        onChange={(e) => patch((d) => (d.routing.tables[idx].name = e.target.value))}
                      />
                    </td>
                    <td>
                      <input
                        type="number"
                        style={{ width: 90 }}
                        value={t.number}
                        disabled={t.system}
                        onChange={(e) =>
                          patch((d) => (d.routing.tables[idx].number = Number(e.target.value)))
                        }
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={t.comment || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.tables[idx].comment = e.target.value))
                        }
                      />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {t.system ? (
                        <Badge tone="neutral">создана netOS</Badge>
                      ) : (
                        <button
                          className="btn ghost sm"
                          onClick={() =>
                            patch(
                              (d) =>
                                (d.routing.tables = d.routing.tables.filter(
                                  (x: any) => x.id !== t.id,
                                )),
                            )
                          }
                        >
                          Удалить
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Card
        title="Правила выбора таблицы"
        subtitle="Какой трафик уходит в какую таблицу. Проверяются по возрастанию приоритета."
        tight
        actions={
          <button
            className="btn sm"
            disabled={(routing.tables || []).length === 0}
            onClick={() =>
              patch((d) => {
                d.routing.rules = d.routing.rules || [];
                const used = d.routing.rules.map((r: any) => r.priority);
                let priority = 20100;
                while (used.includes(priority)) priority += 10;
                d.routing.rules.push({
                  id: "rule-" + Date.now(),
                  name: "Правило",
                  enabled: true,
                  priority,
                  from: "",
                  to: "",
                  fwmark: "",
                  table: d.routing.tables[0]?.name || "",
                });
              })
            }
          >
            Добавить
          </button>
        }
      >
        {(routing.tables || []).length === 0 ? (
          <Empty>Сначала создайте дополнительную таблицу — направлять трафик пока некуда.</Empty>
        ) : (routing.rules || []).length === 0 ? (
          <Empty>Правил нет</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Приоритет</th>
                  <th>Название</th>
                  <th>От кого</th>
                  <th>Куда</th>
                  <th>Метка</th>
                  <th>В таблицу</th>
                  <th>Вкл.</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {[...(routing.rules || [])]
                  .map((r: any, i: number) => ({ r, i }))
                  .sort((a, b) => a.r.priority - b.r.priority)
                  .map(({ r, i }) => (
                    <tr key={r.id}>
                      <td>
                        <input
                          type="number"
                          style={{ width: 90 }}
                          value={r.priority}
                          onChange={(e) =>
                            patch((d) => (d.routing.rules[i].priority = Number(e.target.value)))
                          }
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          style={{ width: 130 }}
                          value={r.name}
                          onChange={(e) => patch((d) => (d.routing.rules[i].name = e.target.value))}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          className="mono"
                          style={{ width: 140 }}
                          placeholder="любой"
                          value={r.from || ""}
                          onChange={(e) => patch((d) => (d.routing.rules[i].from = e.target.value))}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          className="mono"
                          style={{ width: 140 }}
                          placeholder="любой"
                          value={r.to || ""}
                          onChange={(e) => patch((d) => (d.routing.rules[i].to = e.target.value))}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          className="mono"
                          style={{ width: 90 }}
                          placeholder="—"
                          value={r.fwmark || ""}
                          onChange={(e) =>
                            patch((d) => (d.routing.rules[i].fwmark = e.target.value))
                          }
                        />
                      </td>
                      <td>
                        <select
                          value={r.table}
                          onChange={(e) => patch((d) => (d.routing.rules[i].table = e.target.value))}
                        >
                          {tableNames.map((t) => (
                            <option key={t} value={t}>
                              {t}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <Switch
                          checked={r.enabled}
                          label=""
                          onChange={(v) => patch((d) => (d.routing.rules[i].enabled = v))}
                        />
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="btn ghost sm"
                          onClick={() =>
                            patch(
                              (d) =>
                                (d.routing.rules = d.routing.rules.filter(
                                  (x: any) => x.id !== r.id,
                                )),
                            )
                          }
                        >
                          Удалить
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div style={{ padding: "0.8rem 1.1rem", borderTop: "1px solid var(--border)" }}>
          <span className="faint" style={{ fontSize: 12.5 }}>
            Приоритеты 20000–29999 отведены под netOS: остальной диапазон занимает
            система, и правила там лучше не трогать.
          </span>
        </div>
      </Card>

      <Card title="Что сейчас в ядре" subtitle="Фактическое состояние, обновляется каждые 10 секунд">
        {!live ? (
          <Empty>Загрузка…</Empty>
        ) : (
          <>
            <div className="faint" style={{ fontSize: 12, marginBottom: 4 }}>
              Таблица маршрутов
            </div>
            <pre className="output" style={{ borderRadius: "var(--radius-sm)", maxHeight: 200 }}>
              {live.routes || "пусто"}
            </pre>
            <div className="faint" style={{ fontSize: 12, margin: "0.8rem 0 4px" }}>
              Правила выбора таблиц
            </div>
            <pre className="output" style={{ borderRadius: "var(--radius-sm)", maxHeight: 200 }}>
              {live.rules || "пусто"}
            </pre>
          </>
        )}
      </Card>

      {(config.channels || []).filter((c: any) => c.type !== "direct").length === 0 && (
        <Notice tone="info" title="Выбор канала для клиентов появится здесь же">
          Когда будут добавлены VPN-каналы, каждый из них получит собственную таблицу, а
          правила выше начнут направлять в неё трафик выбранных клиентов.
        </Notice>
      )}
    </>
  );
}
