import { interfaceDisplay } from "../interfaceDisplay";
import { useEffect, useState } from "react";
import { api, RouteEntry } from "../api";
import { canonicalTable, observedTables, tableDetails } from "../routingTables";
import { newID } from "../id";
import { Badge, Cap, Card, Empty, Notice, openOnCreate, Row, Rows, Switch, TableWrap } from "../ui";
import { Icon } from "../icons";

type Patch = (mutate: (draft: any) => void) => void;

type RoutesResponse = { routes: string; rules: string; parsed: RouteEntry[] };

// Маршрутизация: куда роутер отправляет пакеты и по какому признаку выбирает
// таблицу. На этом же механизме позже будет построен выбор VPN-канала для
// каждого клиента, поэтому таблицы и правила показаны явно, а не спрятаны.
export function RoutingPage({ config, patch }: { config: any; patch: Patch }) {
  const [live, setLive] = useState<RoutesResponse | null>(null);
  const [liveError, setLiveError] = useState("");
  const [selectedTable, setSelectedTable] = useState("all");

  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const result = await api.routes("all");
        if (!cancelled) {
          setLive(result);
          setLiveError("");
        }
      } catch (cause) {
        if (!cancelled) {
          setLiveError(cause instanceof Error ? cause.message : "Не удалось прочитать маршруты");
        }
      } finally {
        inFlight = false;
      }
    };
    load();
    const t = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const routing = config.routing || { static: [], tables: [], rules: [] };
  const tableNames = ["main", ...(routing.tables || []).map((t: any) => t.name)];

  const observed = observedTables(live?.parsed || [], live?.rules || "");
  const automatic = observed.filter(name => !["main", "local", "default"].includes(name) && !tableDetails(name, config).manual);
  const displayedRoutes = (live?.parsed || []).filter(r => selectedTable === "all" || canonicalTable(r.table || "main") === selectedTable);

  return (
    <>
      <div className="page-head">
        <h1><Icon name="route" />Маршрутизация</h1>
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
                  id: openOnCreate(newID("route")),
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
          <Rows cols={["Название", "Куда", "Через", "Таблица", ""]} toggle="Вкл.">
          {routing.static.map((r: any, idx: number) => (
              <Row
                key={r.id}
                id={r.id}
                cells={[<strong>{r.name}</strong>, <span className="mono">{r.destination || "—"}</span>,
                  r.type && r.type !== "unicast" ? <span className="dim">{ROUTE_TYPE[r.type] || r.type}</span> : <span className="mono">{r.gateway || interfaceDisplay(config, r.interface) || "—"}</span>,
                  <span className="mono">{r.table || "основная"}</span>]}
                toggle={<Switch
                        checked={r.enabled}
                        label=""
                        ariaLabel={`Статический маршрут ${r.destination || idx + 1} включён`}
                        onChange={(v) => patch((d) => (d.routing.static[idx].enabled = v))}
                      />}
              >
                <div className="form-grid">
                  <Cap label="Название"><input
                        type="text"
                        aria-label={`Название статического маршрута ${idx + 1}`}
                        value={r.name}
                        onChange={(e) => patch((d) => (d.routing.static[idx].name = e.target.value))}
                      /></Cap>
                  <Cap label="Куда"><input
                        type="text"
                        aria-label={`Назначение статического маршрута ${r.name || idx + 1}`}
                        className="mono"
                        placeholder="10.0.0.0/8 или default"
                        value={r.destination}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].destination = e.target.value))
                        }
                      /></Cap>
                  <Cap label="Тип"><select
                        value={r.type || "unicast"}
                        onChange={(e) => patch((d) => (d.routing.static[idx].type = e.target.value))}
                        aria-label={`Тип маршрута ${r.name || idx + 1}`}
                      >
                        <option value="unicast">Обычный</option>
                        <option value="blackhole">Отбросить без ответа</option>
                        <option value="unreachable">Сеть недоступна</option>
                        <option value="prohibit">Доступ запрещён</option>
                      </select></Cap>
                  <Cap label="Через шлюз"><input
                        type="text"
                        aria-label={`Шлюз статического маршрута ${r.name || idx + 1}`}
                        className="mono"
                        disabled={r.type && r.type !== "unicast"}
                        value={r.gateway || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].gateway = e.target.value))
                        }
                      /></Cap>
                  <Cap label="Или интерфейс"><input
                        type="text"
                        aria-label={`Интерфейс статического маршрута ${r.name || idx + 1}`}
                        className="mono"
                        disabled={r.type && r.type !== "unicast"}
                        value={r.interface || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].interface = e.target.value))
                        }
                      /></Cap>
                  <Cap label="Метрика"><input
                        type="number"
                        aria-label={`Метрика статического маршрута ${r.name || idx + 1}`}
                        value={r.metric || 0}
                        onChange={(e) =>
                          patch((d) => (d.routing.static[idx].metric = Number(e.target.value)))
                        }
                      /></Cap>
                  <Cap label="Таблица"><select
                        aria-label={`Таблица статического маршрута ${r.name || idx + 1}`}
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
                      </select></Cap>
                </div>
                <div className="row-actions end"><button
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
                      </button></div>
              </Row>
          ))}
        </Rows>
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
                  id: openOnCreate(newID("table")),
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
            Пользовательские таблицы не добавлены.
          </Empty>
        ) : (
          <Rows cols={["Имя", "Номер", "Комментарий", "", ""]}>
          {routing.tables.map((t: any, idx: number) => (
              <Row
                key={t.id}
                id={t.id}
                cells={[<strong className="mono">{t.name}</strong>, <span className="mono">{t.number}</span>, <span className="dim">{t.comment}</span>]}
              >
                <div className="form-grid">
                  <Cap label="Имя"><input
                        type="text"
                        aria-label={`Имя таблицы маршрутизации ${idx + 1}`}
                        className="mono"
                        value={t.name}
                        disabled={t.system}
                        onChange={(e) => patch((d) => (d.routing.tables[idx].name = e.target.value))}
                      /></Cap>
                  <Cap label="Номер"><input
                        type="number"
                        aria-label={`Номер таблицы маршрутизации ${t.name || idx + 1}`}
                        value={t.number}
                        disabled={t.system}
                        onChange={(e) =>
                          patch((d) => (d.routing.tables[idx].number = Number(e.target.value)))
                        }
                      /></Cap>
                  <Cap label="Комментарий"><input
                        type="text"
                        aria-label={`Комментарий таблицы маршрутизации ${t.name || idx + 1}`}
                        value={t.comment || ""}
                        onChange={(e) =>
                          patch((d) => (d.routing.tables[idx].comment = e.target.value))
                        }
                      /></Cap>
                </div>
                <div className="row-actions end">{t.system ? (
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
                      )}</div>
              </Row>
          ))}
        </Rows>
        )}
        {automatic.length > 0 && (
          <TableWrap>
            <table aria-label="Автоматические таблицы маршрутизации">
              <thead><tr><th>Действующая таблица</th><th>Номер</th><th>Назначение</th><th /></tr></thead>
              <tbody>{automatic.map(name => {
                const details = tableDetails(name, config);
                return <tr key={name}><td className="mono">{name}</td><td className="mono">{details.number}</td><td>{details.owner}</td>
                  <td><button className="btn sm" onClick={() => setSelectedTable(name)}>Показать маршруты</button></td></tr>;
              })}</tbody>
            </table>
          </TableWrap>
        )}
        {!live && <Empty>{liveError ? "Действующие таблицы недоступны" : "Загрузка действующих таблиц…"}</Empty>}
        {liveError && live && <Notice tone="danger" title="Данные о таблицах устарели">Не удалось обновить состояние ОС.</Notice>}
      </Card>

      <Card
        title="Правила выбора таблицы"
        subtitle="Выбор пользовательской таблицы маршрутов для заданного трафика. Меньше приоритет — раньше проверка."
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
                  id: openOnCreate(newID("rule")),
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
          <Empty>Для добавления правила создайте пользовательскую таблицу в разделе выше. Таблицами интернет-каналов netOS управляет автоматически: канал выбирается в настройках клиента или сегмента.</Empty>
        ) : (routing.rules || []).length === 0 ? (
          <Empty>Правил нет</Empty>
        ) : (
          <Rows cols={["Название", "От кого", "Куда", "В таблицу", "Приоритет"]} toggle="Вкл.">
          {[...(routing.rules || [])]
                  .map((r: any, i: number) => ({ r, i }))
                  .sort((a, b) => a.r.priority - b.r.priority)
                  .map(({ r, i }) => (
              <Row
                key={r.id}
                id={r.id}
                cells={[<strong>{r.name}</strong>, r.from ? <span className="mono">{r.from}</span> : <span className="dim">любой</span>,
                  r.to ? <span className="mono">{r.to}</span> : <span className="dim">любой</span>,
                  <span className="mono">{r.table}</span>, <span className="mono">{r.priority}</span>]}
                toggle={<Switch
                          checked={r.enabled}
                          label=""
                          ariaLabel={`Правило маршрутизации ${i + 1} включено`}
                          onChange={(v) => patch((d) => (d.routing.rules[i].enabled = v))}
                        />}
              >
                <div className="form-grid">
                  <Cap label="Приоритет"><input
                          type="number"
                          aria-label={`Приоритет правила маршрутизации ${r.name || i + 1}`}
                          value={r.priority}
                          onChange={(e) =>
                            patch((d) => (d.routing.rules[i].priority = Number(e.target.value)))
                          }
                        /></Cap>
                  <Cap label="Название"><input
                          type="text"
                          aria-label={`Название правила маршрутизации ${i + 1}`}
                          value={r.name}
                          onChange={(e) => patch((d) => (d.routing.rules[i].name = e.target.value))}
                        /></Cap>
                  <Cap label="От кого"><input
                          type="text"
                          aria-label={`Источник правила маршрутизации ${r.name || i + 1}`}
                          className="mono"
                          placeholder="любой"
                          value={r.from || ""}
                          onChange={(e) => patch((d) => (d.routing.rules[i].from = e.target.value))}
                        /></Cap>
                  <Cap label="Куда"><input
                          type="text"
                          aria-label={`Назначение правила маршрутизации ${r.name || i + 1}`}
                          className="mono"
                          placeholder="любой"
                          value={r.to || ""}
                          onChange={(e) => patch((d) => (d.routing.rules[i].to = e.target.value))}
                        /></Cap>
                  <Cap label="Входной интерфейс"><input
                          type="text"
                          aria-label={`Входной интерфейс правила маршрутизации ${r.name || i + 1}`}
                          className="mono"
                          placeholder="любой"
                          value={r.interface || ""}
                          onChange={(e) =>
                            patch((d) => (d.routing.rules[i].interface = e.target.value))
                          }
                        /></Cap>
                  <Cap label="Метка"><input
                          type="text"
                          aria-label={`Метка правила маршрутизации ${r.name || i + 1}`}
                          className="mono"
                          placeholder="—"
                          value={r.fwmark || ""}
                          onChange={(e) =>
                            patch((d) => (d.routing.rules[i].fwmark = e.target.value))
                          }
                        /></Cap>
                  <Cap label="В таблицу"><select
                          aria-label={`Таблица правила маршрутизации ${r.name || i + 1}`}
                          value={r.table}
                          onChange={(e) => patch((d) => (d.routing.rules[i].table = e.target.value))}
                        >
                          {tableNames.map((t) => (
                            <option key={t} value={t}>
                              {t}
                            </option>
                          ))}
                        </select></Cap>
                </div>
                <div className="row-actions end"><button
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
                        </button></div>
              </Row>
          ))}
        </Rows>
        )}
        <div className="rows-foot">
          <span className="faint" style={{ fontSize: 12.5 }}>
            Приоритеты 20000–29999 отведены под netOS: остальной диапазон занимает
            система, и правила там лучше не трогать.
          </span>
        </div>
      </Card>

      {liveError && (
        <Notice tone="danger" title="Не удалось обновить действующие маршруты">
          <p>{liveError}</p>
          {live && <p>Показаны последние полученные маршруты и правила. Данные могут быть устаревшими.</p>}
          <p>Повторная попытка выполняется автоматически каждые 10 секунд.</p>
        </Notice>
      )}

      <Card
        title="Действующие маршруты"
        subtitle="Действующие маршруты IPv4 во всех таблицах, включая маршруты VPN-каналов"
        actions={<select aria-label="Показать таблицу маршрутизации" value={selectedTable} onChange={e => setSelectedTable(e.target.value)}>
          <option value="all">Все таблицы</option>
          {[...new Set([...observed, ...(selectedTable !== "all" ? [selectedTable] : [])])].map(name => <option key={name} value={name}>{name}</option>)}
        </select>}
        tight
      >
        {!live ? (
          <Empty>{liveError ? "Действующие маршруты недоступны" : "Загрузка…"}</Empty>
        ) : displayedRoutes.length === 0 ? (
          <Empty>Таблица пуста</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Таблица</th>
                  <th>Куда</th>
                  <th>Через шлюз</th>
                  <th>Интерфейс</th>
                  <th>Метрика</th>
                  <th>Откуда взялся</th>
                </tr>
              </thead>
              <tbody>
                {displayedRoutes.map((r, i) => (
                  <tr key={i}>
                    <td className="mono">{canonicalTable(r.table || "main")}</td>
                    <td className="mono">{r.type && r.type !== "unicast" ? `${r.type} ${r.destination}` : r.destination}</td>
                    <td className="mono">{r.gateway || <span className="faint">напрямую</span>}</td>
                    <td className="mono">{interfaceDisplay(config, r.interface)}</td>
                    <td className="mono">{r.metric || <span className="faint">—</span>}</td>
                    <td>{originBadge(r.origin)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div className="rows-foot">
          <span className="faint" style={{ fontSize: 12.5 }}>
            Маршруты, полученные от провайдера по DHCP, и созданные ядром при назначении
            адреса менять здесь нельзя — они появляются и исчезают сами. Управлять можно
            теми, что заведены выше вручную.
          </span>
        </div>
      </Card>

      <Card title="Правила выбора таблиц в ядре" tight>
        <pre className="output">
          {live ? live.rules || "Правил нет" : liveError ? "Правила недоступны" : "загрузка…"}
        </pre>
      </Card>

      {(config.channels || []).filter((c: any) => c.type !== "direct").length === 0 && (
        <Notice hint tone="info" title="Выбор канала для клиентов появится здесь же">
          Когда будут добавлены VPN-каналы, каждый из них получит собственную таблицу, а
          правила выше начнут направлять в неё трафик выбранных клиентов.
        </Notice>
      )}
    </>
  );
}

// originBadge объясняет, откуда взялся маршрут. Это первое, что нужно знать,
// прежде чем пытаться его исправить: маршрут от провайдера или созданный ядром
// живёт сам по себе, и править его в панели бессмысленно.
const ROUTE_TYPE: Record<string, string> = { blackhole: "отбросить без ответа", unreachable: "сеть недоступна", prohibit: "доступ запрещён" };

function originBadge(origin: string) {
  switch (origin) {
    case "netos":
      return <Badge tone="accent">создан netOS</Badge>;
    case "netos-static":
      return <Badge tone="accent">задан в netOS</Badge>;
    case "static":
      return <Badge tone="accent">статический маршрут</Badge>;
    case "dhcp":
      return <Badge tone="ok">получен от провайдера</Badge>;
    case "kernel":
      return <Badge tone="neutral">создан ядром</Badge>;
    case "boot":
      return <Badge tone="neutral">задан при загрузке</Badge>;
    case "ra":
      return <Badge tone="neutral">анонс маршрутизатора</Badge>;
    default:
      return <Badge tone="neutral">{origin || "неизвестно"}</Badge>;
  }
}
